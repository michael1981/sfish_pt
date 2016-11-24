# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200704-04.xml
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
 script_id(24937);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200704-04");
 script_cve_id("CVE-2006-5616");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200704-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200704-04
(OpenPBS: Multiple vulnerabilities)


    SUSE reported vulnerabilities due to unspecified errors in OpenPBS.
  
Impact

    By unspecified attack vectors an attacker might be able execute
    arbitrary code with the privileges of the user running openpbs, which
    might be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    OpenPBS has been masked in the Portage tree for replacement by Torque.
    All OpenPBS users should unmerge OpenPBS and switch to Torque.
    # emerge --ask --unmerge sys-cluster/openpbs
    # emerge --sync
    # emerge --ask --verbose sys-cluster/torque
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5616');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200704-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200704-04] OpenPBS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenPBS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-cluster/openpbs", unaffected: make_list(), vulnerable: make_list("le 2.3.16-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
