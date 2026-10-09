<?xml version="1.0"?>
<!-- Independent libxslt query over Apple's exported CPU sampling tables. -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:str="http://exslt.org/strings" exclude-result-prefixes="str">
  <xsl:output method="text" encoding="UTF-8"/>
  <xsl:param name="target-pid"/>
  <xsl:key name="cells" match="*[@id]" use="@id"/>

  <xsl:template match="/">
    <xsl:if test="not(number($target-pid) &gt; 0)">
      <xsl:message terminate="yes">invalid oracle target PID</xsl:message>
    </xsl:if>
    <xsl:for-each select="//node[schema/@name='cpu-profile' or schema/@name='time-profile']/row | //table[@schema='cpu-profile' or @schema='time-profile']/row">
      <xsl:variable name="pid">
        <xsl:call-template name="cell">
          <xsl:with-param name="node" select="process[1] | thread[not(../process)][1]"/>
          <xsl:with-param name="kind" select="'pid'"/>
        </xsl:call-template>
      </xsl:variable>
      <!-- Apple emits sentinel instead of a backtrace when no stack is recorded. -->
      <xsl:if test="number($pid)=number($target-pid) and not(sentinel and not(symbol | backtrace | tagged-backtrace))">
        <xsl:if test="count(weight | cycle-weight) != 1">
          <xsl:message terminate="yes">expected one CPU weight cell</xsl:message>
        </xsl:if>
        <xsl:variable name="weight">
          <xsl:call-template name="cell">
            <xsl:with-param name="node" select="weight | cycle-weight"/>
            <xsl:with-param name="kind" select="'weight'"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:if test="not(number($weight)=number($weight)) or number($weight) &lt; 0 or string(number($weight))='Infinity'">
          <xsl:message terminate="yes">invalid CPU weight</xsl:message>
        </xsl:if>
        <xsl:variable name="leaf">
          <xsl:call-template name="cell">
            <xsl:with-param name="node" select="symbol[1] | *[self::backtrace or self::tagged-backtrace][not(../symbol)][1]"/>
            <xsl:with-param name="kind" select="'leaf'"/>
          </xsl:call-template>
        </xsl:variable>
        <xsl:variable name="trimmed">
          <xsl:call-template name="trim"><xsl:with-param name="value" select="string($leaf)"/></xsl:call-template>
        </xsl:variable>
        <xsl:if test="string-length($trimmed)=0">
          <xsl:message terminate="yes">missing leaf symbol</xsl:message>
        </xsl:if>
        <xsl:text>{"symbol":"</xsl:text>
        <xsl:value-of select="str:replace(str:replace(str:replace(str:replace(str:replace(string($trimmed), '\', '\\'), '&quot;', '\&quot;'), '&#10;', '\n'), '&#13;', '\r'), '&#9;', '\t')"/>
        <xsl:text>","weight":</xsl:text><xsl:value-of select="number($weight)"/>
        <xsl:text>,"weight_unit":"</xsl:text>
        <xsl:choose><xsl:when test="cycle-weight">cycles</xsl:when><xsl:otherwise>nanoseconds</xsl:otherwise></xsl:choose>
        <xsl:text>"}&#10;</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="cell">
    <xsl:param name="node"/>
    <xsl:param name="kind"/>
    <xsl:param name="seen" select="'|'"/>
    <xsl:choose>
      <xsl:when test="$node/@ref">
        <xsl:variable name="reference" select="string($node/@ref)"/>
        <xsl:if test="contains($seen, concat('|', $reference, '|')) or count(key('cells', $reference)) != 1">
          <xsl:message terminate="yes">missing, ambiguous, or cyclic CPU cell reference</xsl:message>
        </xsl:if>
        <xsl:call-template name="cell">
          <xsl:with-param name="node" select="key('cells', $reference)"/>
          <xsl:with-param name="kind" select="$kind"/>
          <xsl:with-param name="seen" select="concat($seen, $reference, '|')"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$kind='pid' and $node/@pid"><xsl:value-of select="$node/@pid"/></xsl:when>
      <xsl:when test="$kind='pid' and name($node)='pid'"><xsl:value-of select="$node"/></xsl:when>
      <xsl:when test="$kind='pid' and $node/*[self::pid or self::process]">
        <xsl:call-template name="cell">
          <xsl:with-param name="node" select="$node/*[self::pid or self::process][1]"/>
          <xsl:with-param name="kind" select="$kind"/>
          <xsl:with-param name="seen" select="$seen"/>
        </xsl:call-template>
      </xsl:when>
      <xsl:when test="$kind='weight'"><xsl:value-of select="$node"/></xsl:when>
      <xsl:when test="$kind='leaf' and $node[self::frame or self::symbol]">
        <xsl:choose><xsl:when test="$node/@name"><xsl:value-of select="$node/@name"/></xsl:when><xsl:otherwise><xsl:value-of select="$node/text()[1]"/></xsl:otherwise></xsl:choose>
      </xsl:when>
      <xsl:when test="$kind='leaf' and $node/*[self::frame or self::backtrace]">
        <xsl:call-template name="cell">
          <xsl:with-param name="node" select="$node/*[self::frame or self::backtrace][1]"/>
          <xsl:with-param name="kind" select="$kind"/>
          <xsl:with-param name="seen" select="$seen"/>
        </xsl:call-template>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template name="trim">
    <xsl:param name="value"/>
    <xsl:choose>
      <xsl:when test="string-length($value) &gt; 0 and contains(' &#9;&#10;&#13;', substring($value, 1, 1))">
        <xsl:call-template name="trim"><xsl:with-param name="value" select="substring($value, 2)"/></xsl:call-template>
      </xsl:when>
      <xsl:when test="string-length($value) &gt; 0 and contains(' &#9;&#10;&#13;', substring($value, string-length($value), 1))">
        <xsl:call-template name="trim"><xsl:with-param name="value" select="substring($value, 1, string-length($value)-1)"/></xsl:call-template>
      </xsl:when>
      <xsl:otherwise><xsl:value-of select="$value"/></xsl:otherwise>
    </xsl:choose>
  </xsl:template>
</xsl:stylesheet>
