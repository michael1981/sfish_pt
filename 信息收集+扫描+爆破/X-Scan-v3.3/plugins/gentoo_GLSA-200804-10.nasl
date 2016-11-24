# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-10.xml
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
 script_id(31957);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200804-10");
 script_cve_id("CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-6286", "CVE-2008-0002");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-10
(Tomcat: Multiple vulnerabilities)


    The following vulnerabilities were reported:
    Delian Krustev discovered that the JULI logging component does not
    properly enforce access restrictions, allowing web application to add
    or overwrite files (CVE-2007-5342).
    When the native APR connector is used, Tomcat does not properly handle
    an empty request to the SSL port, which allows remote attackers to
    trigger handling of a duplicate copy of one of the recent requests
    (CVE-2007-6286).
    If the processing or parameters is interrupted, i.e. by an exception,
    then it is possible for the parameters to be processed as part of later
    request (CVE-2008-0002).
    An absolute path traversal vulnerability exists due to the way that
    WebDAV write requests are handled (CVE-2007-5461).
    Tomcat does not properly handle double quote (") characters or %5C
    (encoded backslash) sequences in a cookie value, which might cause
    sensitive information such as session IDs to be leaked to remote
    attackers and enable session hijacking attacks
    (CVE-2007-5333).
  
Impact

    These vulnerabilities can be exploited by:
    a malicious web application to add or overwrite files with the
    permissions of the user running Tomcat.
    a remote attacker to conduct session hijacking or disclose sensitive
    data.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Tomcat 5.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/tomcat-5.5.26"
    All Tomcat 6.0.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/tomcat-6.0.16"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5333');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5342');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5461');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6286');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0002');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-10] Tomcat: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tomcat: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/tomcat", unaffected: make_list("rge 5.5.26", "ge 6.0.16", "rge 5.5.27"), vulnerable: make_list("lt 6.0.16")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
