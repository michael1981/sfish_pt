# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-04.xml
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
 script_id(17978);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200504-04");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-04
(mit-krb5: Multiple buffer overflows in telnet client)


    A buffer overflow has been identified in the env_opt_add()
    function, where a response requiring excessive escaping can cause a
    heap-based buffer overflow. Another issue has been identified in the
    slc_add_reply() function, where a large number of SLC commands can
    overflow a fixed size buffer.
  
Impact

    Successful exploitation would require a vulnerable user to connect
    to an attacker-controlled telnet host, potentially executing arbitrary
    code with the permissions of the telnet user on the client.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mit-krb5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.3.6-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0468');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0469');
script_set_attribute(attribute: 'see_also', value: 'http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2005-001-telnet.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-04] mit-krb5: Multiple buffer overflows in telnet client');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mit-krb5: Multiple buffer overflows in telnet client');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.3.6-r2"), vulnerable: make_list("lt 1.3.6-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
