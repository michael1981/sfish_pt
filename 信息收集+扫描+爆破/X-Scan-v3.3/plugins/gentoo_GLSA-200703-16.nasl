# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-16.xml
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
 script_id(24841);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-16");
 script_cve_id("CVE-2007-0774");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-16
(Apache JK Tomcat Connector: Remote execution of arbitrary code)


    ZDI reported an unsafe memory copy in mod_jk that was discovered by an
    anonymous researcher in the map_uri_to_worker function of
    native/common/jk_uri_worker_map.c .
  
Impact

    A remote attacker can send a long URL request to an Apache server using
    Tomcat. That can trigger the vulnerability and lead to a stack-based
    buffer overflow, which could result in the execution of arbitrary code
    with the permissions of the Apache user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache Tomcat users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/mod_jk-1.2.21-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0774');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-16] Apache JK Tomcat Connector: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache JK Tomcat Connector: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apache/mod_jk", unaffected: make_list("ge 1.2.21-r1"), vulnerable: make_list("lt 1.2.21-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
