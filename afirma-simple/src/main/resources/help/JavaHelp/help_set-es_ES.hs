<?xml version='1.0' encoding='ISO-8859-1'?>
<!DOCTYPE helpset PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 1.0//EN" "http://java.sun.com/products/javahelp/helpset_1_0.dtd">

<helpset version="1.0">
  <title>Ayuda</title>
  <maps>
    <!-- Página padrão ao mostrar a ajuda -->
    <homeID>aplicacion</homeID>
    <!-- Que mapa deseamos -->
    <mapref location="map_file-es.jhm" />
  </maps>

  <!-- As Visões que desejamos mostrar na ajuda -->
  <view>
    <name>Tabela de Conteúdos</name>
    <label>Tabela de conteúdos</label>
    <type>javax.help.TOCView</type>
    <data>toc-es.xml</data>
  </view>

  <view>
    <name>Índice</name>
    <label>O índice</label>
    <type>javax.help.IndexView</type>
    <data>index-es.xml</data>
  </view>

  <!--
  <view>
    <name>Buscar</name>
    <label>Buscar</label>
    <type>javax.help.SearchView</type>
    <data engine="test.Busqueda">
      JavaHelpSearch
    </data>
  </view>
  -->
</helpset>