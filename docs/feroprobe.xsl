<?xml version="1.0" encoding="UTF-8"?>
<!--
  feroprobe.xsl: shows a FeroProbe XML report (-oX) as a web page.

  Written for FeroProbe; not derived from nmap's nmap.xsl. It reads the
  nmap-compatible element names FeroProbe writes, so it also shows reports
  from other scanners that use that layout.

  Use it with a browser that applies XSLT to local files, or convert a report:
    xsltproc -o report.html feroprobe.xsl report.xml

  SPDX-License-Identifier: GPL-3.0-or-later
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes"
              doctype-system="about:legacy-compat"/>

  <xsl:template match="/">
    <xsl:apply-templates select="nmaprun[1]"/>
  </xsl:template>

  <xsl:template match="nmaprun">
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Scan report: <xsl:value-of select="@startstr"/></title>
        <style>
          :root {
            --bg: #ffffff; --fg: #1d2330; --muted: #5d6677; --line: #d9dee7;
            --head: #f2f4f8; --open: #1a7f37; --closed: #b42318; --filtered: #9a6700;
            --link: #0b5cad;
          }
          @media (prefers-color-scheme: dark) {
            :root {
              --bg: #14171d; --fg: #e4e8ef; --muted: #9aa3b2; --line: #2e3440;
              --head: #1d222b; --open: #4ac26b; --closed: #ff7b72; --filtered: #d4a72c;
              --link: #6cb6ff;
            }
          }
          body { background: var(--bg); color: var(--fg); margin: 0 auto;
                 max-width: 72rem; padding: 1.5rem 1rem 3rem;
                 font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
          h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
          h2 { font-size: 1.2rem; margin: 2rem 0 .5rem; padding-bottom: .25rem;
               border-bottom: 1px solid var(--line); }
          h3 { font-size: 1rem; margin: 1.25rem 0 .4rem; }
          a { color: var(--link); }
          code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                        font-size: .9em; }
          .muted { color: var(--muted); }
          .scroll { overflow-x: auto; }
          table { border-collapse: collapse; width: 100%; margin: .25rem 0 .75rem; }
          th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid var(--line);
                   vertical-align: top; }
          th { background: var(--head); font-weight: 600; }
          .open, .up { color: var(--open); font-weight: 600; }
          .closed, .down { color: var(--closed); }
          .filtered, .unfiltered, .open-filtered, .closed-filtered { color: var(--filtered); }
          pre { background: var(--head); padding: .6rem; overflow-x: auto; margin: .25rem 0; }
          dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem 1rem; margin: .5rem 0; }
          dt { color: var(--muted); }
          dd { margin: 0; overflow-wrap: anywhere; }
        </style>
      </head>
      <body>
        <h1>Scan report</h1>
        <p class="muted">
          <xsl:value-of select="@scanner"/>
          <xsl:text> </xsl:text>
          <xsl:value-of select="@version"/>
          <xsl:text>, started </xsl:text>
          <xsl:value-of select="@startstr"/>
        </p>
        <dl>
          <dt>Command</dt>
          <dd><code><xsl:value-of select="@args"/></code></dd>
          <xsl:for-each select="scaninfo">
            <dt>Scan</dt>
            <dd>
              <xsl:value-of select="@type"/>
              <xsl:text> (</xsl:text>
              <xsl:value-of select="@protocol"/>
              <xsl:text>, </xsl:text>
              <xsl:value-of select="@numservices"/>
              <xsl:text> ports or protocols)</xsl:text>
            </dd>
          </xsl:for-each>
          <xsl:for-each select="runstats/finished">
            <dt>Finished</dt>
            <dd>
              <xsl:value-of select="@timestr"/>
              <xsl:text> after </xsl:text>
              <xsl:value-of select="@elapsed"/>
              <xsl:text> s</xsl:text>
            </dd>
          </xsl:for-each>
          <xsl:for-each select="runstats/hosts">
            <dt>Hosts</dt>
            <dd>
              <xsl:value-of select="@up"/> up, <xsl:value-of select="@down"/> down,
              <xsl:value-of select="@total"/> in total
            </dd>
          </xsl:for-each>
        </dl>

        <xsl:if test="host">
          <h2>Hosts</h2>
          <div class="scroll">
            <table>
              <tr><th>Address</th><th>Name</th><th>State</th><th>Open ports</th></tr>
              <xsl:for-each select="host">
                <tr>
                  <td class="mono">
                    <a href="#{generate-id(.)}"><xsl:value-of select="address[@addrtype!='mac'][1]/@addr"/></a>
                  </td>
                  <td><xsl:value-of select="hostnames/hostname[1]/@name"/></td>
                  <td class="{status/@state}"><xsl:value-of select="status/@state"/></td>
                  <td><xsl:value-of select="count(ports/port[state/@state='open'])"/></td>
                </tr>
              </xsl:for-each>
            </table>
          </div>
          <xsl:apply-templates select="host"/>
        </xsl:if>

        <xsl:for-each select="prescript|postscript">
          <h2><xsl:value-of select="local-name()"/> output</h2>
          <xsl:apply-templates select="script"/>
        </xsl:for-each>

        <p class="muted">
          <xsl:value-of select="runstats/finished/@summary"/>
        </p>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="host">
    <h2 id="{generate-id(.)}">
      <xsl:value-of select="address[@addrtype!='mac'][1]/@addr"/>
      <xsl:if test="hostnames/hostname">
        <xsl:text> (</xsl:text>
        <xsl:value-of select="hostnames/hostname[1]/@name"/>
        <xsl:text>)</xsl:text>
      </xsl:if>
    </h2>
    <dl>
      <dt>State</dt>
      <dd>
        <span class="{status/@state}"><xsl:value-of select="status/@state"/></span>
        <xsl:if test="status/@reason">
          <span class="muted"> (<xsl:value-of select="status/@reason"/>)</span>
        </xsl:if>
      </dd>
      <xsl:for-each select="address">
        <dt>Address (<xsl:value-of select="@addrtype"/>)</dt>
        <dd class="mono">
          <xsl:value-of select="@addr"/>
          <xsl:if test="@vendor"> (<xsl:value-of select="@vendor"/>)</xsl:if>
        </dd>
      </xsl:for-each>
      <xsl:for-each select="hostnames/hostname">
        <dt>Name (<xsl:value-of select="@type"/>)</dt>
        <dd><xsl:value-of select="@name"/></dd>
      </xsl:for-each>
      <xsl:for-each select="distance">
        <dt>Network distance</dt>
        <dd><xsl:value-of select="@value"/> hop(s)</dd>
      </xsl:for-each>
      <xsl:for-each select="times">
        <dt>Round trip</dt>
        <dd><xsl:value-of select="@srtt"/> µs (smoothed)</dd>
      </xsl:for-each>
    </dl>

    <xsl:apply-templates select="ports"/>
    <xsl:apply-templates select="os"/>
    <xsl:apply-templates select="trace"/>
    <xsl:if test="hostscript/script">
      <h3>Host scripts</h3>
      <xsl:apply-templates select="hostscript/script"/>
    </xsl:if>
  </xsl:template>

  <xsl:template match="ports">
    <h3>Ports</h3>
    <xsl:for-each select="extraports">
      <p class="muted">
        Not shown: <xsl:value-of select="@count"/>
        <xsl:text> </xsl:text>
        <xsl:value-of select="@state"/> ports
      </p>
    </xsl:for-each>
    <xsl:choose>
      <xsl:when test="port">
        <div class="scroll">
          <table>
            <tr>
              <th>Port</th><th>State</th><th>Reason</th><th>Service</th><th>Version</th>
            </tr>
            <xsl:for-each select="port">
              <tr>
                <td class="mono"><xsl:value-of select="@portid"/>/<xsl:value-of select="@protocol"/></td>
                <td class="{translate(state/@state, '|', '-')}"><xsl:value-of select="state/@state"/></td>
                <td class="muted"><xsl:value-of select="state/@reason"/></td>
                <td><xsl:value-of select="service/@name"/></td>
                <td>
                  <xsl:value-of select="service/@product"/>
                  <xsl:if test="service/@version">
                    <xsl:text> </xsl:text><xsl:value-of select="service/@version"/>
                  </xsl:if>
                  <xsl:if test="service/@extrainfo">
                    <xsl:text> (</xsl:text><xsl:value-of select="service/@extrainfo"/><xsl:text>)</xsl:text>
                  </xsl:if>
                  <xsl:for-each select="service/cpe">
                    <div class="mono muted"><xsl:value-of select="."/></div>
                  </xsl:for-each>
                </td>
              </tr>
              <xsl:if test="script">
                <tr><td colspan="5"><xsl:apply-templates select="script"/></td></tr>
              </xsl:if>
            </xsl:for-each>
          </table>
        </div>
      </xsl:when>
      <xsl:when test="not(extraports)">
        <p class="muted">No ports reported.</p>
      </xsl:when>
    </xsl:choose>
  </xsl:template>

  <xsl:template match="os">
    <xsl:if test="osmatch or osfingerprint">
      <h3>Operating system</h3>
      <xsl:if test="osmatch">
        <div class="scroll">
          <table>
            <tr><th>Match</th><th>Accuracy</th><th>Type</th><th>CPE</th></tr>
            <xsl:for-each select="osmatch">
              <tr>
                <td><xsl:value-of select="@name"/></td>
                <td><xsl:value-of select="@accuracy"/>%</td>
                <td><xsl:value-of select="osclass[1]/@type"/></td>
                <td class="mono"><xsl:value-of select="osclass[1]/cpe[1]"/></td>
              </tr>
            </xsl:for-each>
          </table>
        </div>
      </xsl:if>
      <xsl:for-each select="osfingerprint">
        <p class="muted">Fingerprint:</p>
        <pre><xsl:value-of select="@fingerprint"/></pre>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>

  <xsl:template match="trace">
    <h3>Route</h3>
    <div class="scroll">
      <table>
        <tr><th>Hop</th><th>Round trip</th><th>Address</th><th>Name</th></tr>
        <xsl:for-each select="hop">
          <tr>
            <td><xsl:value-of select="@ttl"/></td>
            <td><xsl:value-of select="@rtt"/> ms</td>
            <td class="mono"><xsl:value-of select="@ipaddr"/></td>
            <td><xsl:value-of select="@host"/></td>
          </tr>
        </xsl:for-each>
      </table>
    </div>
  </xsl:template>

  <xsl:template match="script">
    <p><strong><xsl:value-of select="@id"/></strong></p>
    <pre><xsl:value-of select="@output"/></pre>
  </xsl:template>
</xsl:stylesheet>
