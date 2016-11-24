# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-06.xml
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
 script_id(14471);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200404-06");
 script_cve_id("CVE-2004-0080");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-06
(Util-linux login may leak sensitive data)


    In some situations the login program could leak sensitive data due to an
    incorrect usage of a reallocated pointer.
	NOTE: Only users who have PAM support disabled on their
	systems (i.e.  -PAM in their USE variable) will be affected by this
	vulnerability.  By default, this USE flag is enabled on all
	architectures.  Users with PAM support on their system receive login binaries
	as part of the pam-login package, which remains unaffected.
  
Impact

    A remote attacker may obtain sensitive data.
  
Workaround

     A workaround is not currently known for this issue. All users are advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    All util-linux users should upgrade to version 2.12 or later:
    # emerge sync
	# emerge -pv ">=sys-apps/util-linux-2.12"
    # emerge ">=sys-apps/util-linux-2.12"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0080');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-06] Util-linux login may leak sensitive data');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Util-linux login may leak sensitive data');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/util-linux", unaffected: make_list("ge 2.12"), vulnerable: make_list("le 2.11")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
