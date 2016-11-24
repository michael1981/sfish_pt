# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-01.xml
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
 script_id(26941);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-01");
 script_cve_id("CVE-2007-3999");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-01
(RPCSEC_GSS library: Buffer overflow)


    A stack based buffer overflow has been discovered in the
    svcauth_gss_validate() function in file lib/rpc/svc_auth_gss.c when
    processing an overly long string in a RPC message.
  
Impact

    A remote attacker could send a specially crafted RPC request to an
    application relying on this library, e.g NFSv4 or Kerberos
    (GLSA-200709-01), resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All librpcsecgss users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/librpcsecgss-0.16"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3999');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-01.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-01] RPCSEC_GSS library: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RPCSEC_GSS library: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-libs/librpcsecgss", unaffected: make_list("ge 0.16"), vulnerable: make_list("lt 0.16")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
