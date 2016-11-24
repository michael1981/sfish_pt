# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-21.xml
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
 script_id(24257);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200701-21");
 script_cve_id("CVE-2006-6143", "CVE-2006-6144");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-21
(MIT Kerberos 5: Arbitrary Remote Code Execution)


    The Kerberos administration daemon, and possibly other applications
    using the GSS-API or RPC libraries, could potentially call a function
    pointer in a freed heap buffer, or attempt to free an uninitialized
    pointer.
  
Impact

    A remote attacker may be able to crash an affected application, or
    potentially execute arbitrary code with root privileges.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.5.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6143');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6144');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-21] MIT Kerberos 5: Arbitrary Remote Code Execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Arbitrary Remote Code Execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.5.2"), vulnerable: make_list("lt 1.5.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
