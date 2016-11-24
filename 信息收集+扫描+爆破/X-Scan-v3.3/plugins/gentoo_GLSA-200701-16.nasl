# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(24252);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200701-16");
 script_cve_id("CVE-2006-5857", "CVE-2007-0044", "CVE-2007-0045", "CVE-2007-0046", "CVE-2007-0048");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-16
(Adobe Acrobat Reader: Multiple vulnerabilities)


    Adobe Acrobat Reader in stand-alone mode is vulnerable to remote code
    execution via heap corruption when loading a specially crafted PDF
    file.
    The browser plugin released with Adobe Acrobat Reader (nppdf.so) does
    not properly handle URLs, and crashes if given a URL that is too long.
    The plugin does not correctly handle JavaScript, and executes
    JavaScript that is given as a GET variable to the URL of a PDF file.
    Lastly, the plugin does not properly handle the FDF, xml, xfdf AJAX
    request parameters following the # character in a URL, allowing for
    multiple cross-site scripting vulnerabilities.
  
Impact

    An attacker could entice a user to open a specially crafted PDF file
    and execute arbitrary code with the rights of the user running Adobe
    Acrobat Reader. An attacker could also entice a user to browse to a
    specially crafted URL and either crash the Adobe Acrobat Reader browser
    plugin, execute arbitrary JavaScript in the context of the user\'s
    browser, or inject arbitrary HTML or JavaScript into the document being
    viewed by the user. Note that users who have emerged Adobe Acrobat
    Reader with the "nsplugin" USE flag disabled are not vulnerable to
    issues with the Adobe Acrobat Reader browser plugin.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Acrobat Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-7.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5857');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0044');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0045');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0046');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0048');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-16] Adobe Acrobat Reader: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Acrobat Reader: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 7.0.9"), vulnerable: make_list("lt 7.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
