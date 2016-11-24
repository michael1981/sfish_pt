# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-03.xml
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
 script_id(25133);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200705-03");
 script_cve_id("CVE-2007-0450");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-03
(Tomcat: Information disclosure)


    Tomcat allows special characters like slash, backslash or URL-encoded
    backslash as a separator, while Apache does not.
  
Impact

    A remote attacker could send a specially crafted URL to the vulnerable
    Tomcat server, possibly resulting in a directory traversal and read
    access to arbitrary files with the privileges of the user running
    Tomcat. Note that this vulnerability can only be exploited when using
    apache proxy modules like mod_proxy, mod_rewrite or mod_jk.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tomcat users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/tomcat-5.5.22"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0450');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-03] Tomcat: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tomcat: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/tomcat", unaffected: make_list("ge 5.5.22"), vulnerable: make_list("lt 5.5.22")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
