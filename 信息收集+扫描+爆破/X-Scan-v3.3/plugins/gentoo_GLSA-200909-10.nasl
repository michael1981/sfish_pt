# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-10.xml
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
 script_id(40918);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200909-10");
 script_cve_id("CVE-2008-4968");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-10
(LMBench: Insecure temporary file usage)


    Dmitry E. Oboukhov reported that the rccs and STUFF scripts do not
    handle "/tmp/sdiff.#####" temporary files securely. NOTE: There might
    be further occurances of insecure temporary file usage.
  
Impact

    A local attacker could perform symlink attacks to overwrite arbitrary
    files with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    LMBench has been removed from Portage. We recommend that users unmerge
    LMBench:
    # emerge --unmerge app-benchmarks/lmbench
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4968');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-10] LMBench: Insecure temporary file usage');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LMBench: Insecure temporary file usage');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-benchmarks/lmbench", unaffected: make_list(), vulnerable: make_list("le 3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
