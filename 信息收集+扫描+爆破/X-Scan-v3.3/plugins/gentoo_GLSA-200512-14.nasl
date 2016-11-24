# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-14.xml
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
 script_id(20355);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-14");
 script_cve_id("CVE-2005-3534");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-14
(NBD Tools: Buffer overflow in NBD server)


    Kurt Fitzner discovered that the NBD server allocates a request
    buffer that fails to take into account the size of the reply header.
  
Impact

    A remote attacker could send a malicious request that can result
    in the execution of arbitrary code with the rights of the NBD server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All NBD Tools users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-block/nbd-2.8.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3534');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-14] NBD Tools: Buffer overflow in NBD server');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NBD Tools: Buffer overflow in NBD server');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-block/nbd", unaffected: make_list("ge 2.8.2-r1"), vulnerable: make_list("lt 2.8.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
