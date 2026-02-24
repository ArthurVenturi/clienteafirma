/* Copyright (C) 2011 [Governo da Espanha]
 * Este arquivo faz parte do "Cliente @Firma".
 * "Cliente @Firma" é um software livre; você pode redistribuí-lo e/ou modificá-lo sob os termos de:
 *   - GNU General Public License conforme publicada pela Free Software Foundation;
 *     versão 2 da Licença, ou (a seu critério) qualquer versão posterior.
 *   - ou The European Software License; versão 1.1 ou (a seu critério) qualquer versão posterior.
 * Você pode entrar em contato com o detentor dos direitos autorais em: suporte.afirma@seap.minhap.es
 */

package es.gob.afirma.keystores;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.PasswordCallback;

import es.gob.afirma.core.AOCancelledOperationException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.keystores.callbacks.UIPasswordCallback;

final class AOKeyStoreManagerHelperPkcs11 {

	static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private AOKeyStoreManagerHelperPkcs11() {
		// No permitimos la instanciacion
	}

    /** Inicializa um repositório PKCS#11.
     * @param pssCallBack Callback para recuperação da senha do repositório.
     * @param params Parâmetros adicionais para configuração do repositório.
     * @param forceReset Indica se deve forçar o reinício do repositório.
     * @param parent Componente pai sobre o qual mostrar os diálogos gráficos.
     * @return Repositório configurado.
     * @throws AOKeyStoreManagerException Quando ocorre um erro durante a inicialização.
     * @throws IOException Quando uma senha incorreta é informada para abertura do repositório.
     * @throws es.gob.afirma.core.AOCancelledOperationException Quando algum diálogo de PIN é cancelado. */
    static KeyStore initPKCS11(final PasswordCallback pssCallBack,
    		                   final Object[] params,
    		                   final boolean forceReset,
    		                   final Object parent) throws AOKeyStoreManagerException,
    		                                                 IOException {
                // Em "params" devemos trazer os parâmetros:
                // [0] -p11lib: Biblioteca PKCS#11, deve estar no Path (Windows) ou no LD_LIBRARY_PATH (UNIX, Linux, Mac OS X)
                // [1] -desc: Descrição do token PKCS#11 (opcional)
                // [2] -slot: Número do leitor de cartão (Sistema Operacional) [OPCIONAL]

                // Adicionamos o provedor PKCS11 da Sun
                if (params == null || params.length < 2) {
                        throw new IOException(
                		"Não é possível acessar o KeyStore PKCS#11 se a biblioteca não for especificada" //$NON-NLS-1$
        		);
                }
        final String p11lib;
                if (params[0] != null) {
                        p11lib = params[0].toString();
                }
                else {
                        throw new IllegalArgumentException(
                		"Não é possível acessar o KeyStore PKCS#11 se uma biblioteca nula for especificada" //$NON-NLS-1$
        		);
                }

        // Número do leitor
        Integer slot = null;
        if (params.length >= 3 && params[2] instanceof Integer) {
            slot = (Integer) params[2];
        }

        // Adicionamos um nome a cada PKCS#11 para garantir que não sejam adicionados mais de uma vez como Provider.
        // Se o PKCS#11 já foi carregado anteriormente, será reiniciado.
        final String p11ProviderName = new File(p11lib).getName().replace('.', '_').replace(' ', '_');
        Provider p11Provider = Security.getProvider("SunPKCS11-" + p11ProviderName); //$NON-NLS-1$


        if (p11Provider != null && (forceReset || Boolean.getBoolean("es.gob.afirma.keystores.DoNotReusePkcs11Provider"))) { //$NON-NLS-1$
        	LOGGER.info("Removendo o provedor " + p11Provider); //$NON-NLS-1$
        	Security.removeProvider(p11Provider.getName());
        	p11Provider = null;
        }

        if (p11Provider == null) {

            final byte[] config = KeyStoreUtilities.createPKCS11ConfigFile(p11lib, p11ProviderName, slot).getBytes();
            try {
                p11Provider = getP11Provider(config);
            }
            catch (final Exception e) {
            	LOGGER.warning(
        			"Falha na primeira tentativa de inicialização do PKCS#11 para a biblioteca '" + p11lib + "', tentando novamente: " + e //$NON-NLS-1$ //$NON-NLS-2$
    			);
                // O PKCS#11 do DNIe às vezes falha na primeira, mas funciona corretamente na segunda, então tentamos novamente
                try {
                    p11Provider = getP11Provider(config);
                }
                catch (final Exception ex) {
                	LOGGER.log(Level.WARNING,
                			"Falha na segunda tentativa de inicialização do PKCS#11 para a biblioteca " + p11lib, e //$NON-NLS-1$
            		);
                    throw new AOKeyStoreManagerException(
                		"Não foi possível instanciar o provedor SunPKCS11 para a biblioteca '" + p11lib + "': " + ex, ex  //$NON-NLS-1$//$NON-NLS-2$
            		);
                }
            }
        }
        else {
            LOGGER.info(
        		"O provedor SunPKCS11 solicitado já estava instanciado, reutilizando essa instância: " + p11Provider.getName() //$NON-NLS-1$
    		);
        }

        if (pssCallBack == null) {
        	return getKeyStoreWithNullPassword(p11Provider);
        } else if (pssCallBack instanceof UIPasswordCallback) {
			final String promptText = KeyStoreMessages.getString("AOKeyStore.15", AOKeyStore.PKCS11.getName()); //$NON-NLS-1$
			((UIPasswordCallback) pssCallBack).setPrompt(promptText);
		}
        try {
			return KeyStoreUtilities.getKeyStoreWithPasswordCallbackHandler(
				AOKeyStore.PKCS11,
				pssCallBack,
				p11Provider,
				parent
			);
		}
        catch (final AOCancelledOperationException e) {
        	// Remove o provedor se o usuário cancelar o uso do cartão
        	Security.removeProvider("SunPKCS11-" + p11ProviderName); //$NON-NLS-1$
        	throw e;
        }
        catch (final Exception e) {
        	// Em caso de não conseguir instanciar o cartão, remove o provedor
        	Security.removeProvider("SunPKCS11-" + p11ProviderName); //$NON-NLS-1$
        	throw new AOKeyStoreManagerException(
        		"Erro ao construir o KeyStore PKCS#11 para a biblioteca '" + p11lib + "': " + e, e //$NON-NLS-1$ //$NON-NLS-2$
        	);
        }
    }

    private static KeyStore getKeyStoreWithNullPassword(final Provider p11Provider) throws AOKeyStoreManagerException {
        final KeyStore ks;
        try {
            ks = KeyStore.getInstance(AOKeyStore.PKCS11.getProviderName(), p11Provider);
        }
        catch (final Exception e) {
            Security.removeProvider(p11Provider.getName());
            throw new AOKeyStoreManagerException("Não foi possível obter o repositório PKCS#11: " + e, e); //$NON-NLS-1$
        }

        try {
        	ks.load(null, null);
        }
        catch (final IOException e) {
            throw new AOKeyStoreManagerException(
        		"Não foi possível obter o repositório PKCS#11 solicitado: " + e, e //$NON-NLS-1$
    		);
        }
        catch (final CertificateException e) {
            Security.removeProvider(p11Provider.getName());
            throw new AOKeyStoreManagerException(
        		"Não foi possível carregar os certificados do repositório PKCS#11 solicitado: " + e, e //$NON-NLS-1$
    		);
        }
        catch (final NoSuchAlgorithmException e) {
            Security.removeProvider(p11Provider.getName());
            throw new AOKeyStoreManagerException(
        		"Não foi possível verificar a integridade do repositório PKCS#11 solicitado: " + e, e //$NON-NLS-1$
    		);
		}
        return ks;
    }

    private static Provider getP11Provider(final byte[] p11NSSConfigFileContents) throws NoSuchMethodException,
                                                                                         SecurityException,
                                                                                         IllegalAccessException,
                                                                                         IllegalArgumentException,
                                                                                         InvocationTargetException,
                                                                                         InstantiationException,
                                                                                         ClassNotFoundException,
                                                                                         IOException {
    	return AOUtil.isJava9orNewer() ?
			getP11ProviderJava9(p11NSSConfigFileContents) :
				getP11ProviderJava8(p11NSSConfigFileContents);
    }

	private static Provider getP11ProviderJava9(final byte[] p11NSSConfigFileContents) throws IOException,
	                                                                                          NoSuchMethodException,
	                                                                                          SecurityException,
	                                                                                          IllegalAccessException,
	                                                                                          IllegalArgumentException,
	                                                                                          InvocationTargetException {
		final Provider p = Security.getProvider("SunPKCS11"); //$NON-NLS-1$
		final File f = File.createTempFile("pkcs11_", ".cfg");  //$NON-NLS-1$//$NON-NLS-2$
		try (
			final OutputStream fos = new FileOutputStream(f);
		) {
			fos.write(p11NSSConfigFileContents);
			fos.close();
		}
		final Method configureMethod = Provider.class.getMethod("configure", String.class); //$NON-NLS-1$
		final Provider configuredProvider = (Provider) configureMethod.invoke(p, f.getAbsolutePath());
		f.deleteOnExit();
		Security.addProvider(configuredProvider);
		return configuredProvider;
	}

	private static Provider getP11ProviderJava8(final byte[] p11NSSConfigFileContents) throws InstantiationException,
	                                                                                          IllegalAccessException,
	                                                                                          IllegalArgumentException,
	                                                                                          InvocationTargetException,
	                                                                                          NoSuchMethodException,
	                                                                                          SecurityException,
	                                                                                          ClassNotFoundException {
		final Provider p = (Provider) Class.forName("sun.security.pkcs11.SunPKCS11") //$NON-NLS-1$
				.getConstructor(InputStream.class)
					.newInstance(new ByteArrayInputStream(p11NSSConfigFileContents));
        Security.addProvider(p);
        return p;
	}

}
