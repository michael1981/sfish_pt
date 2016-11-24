# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-25.xml
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
 script_id(21758);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-25");
 script_cve_id("CVE-2006-3251");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-25
(Hashcash: Possible heap overflow)


    Andreas Seltenreich has reported a possible heap overflow in the
    array_push() function in hashcash.c, as a result of an incorrect amount
    of allocated memory for the "ARRAY" structure.
  
Impact

    By sending malicious entries to the Hashcash utility, an attacker may
    be able to cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Hashcash users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/hashcash-1.21"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.hashcash.org/source/CHANGELOG');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3251');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-25] Hashcash: Possible heap overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Hashcash: Possible heap overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/hashcash", unaffected: make_list("ge 1.21"), vulnerable: make_list("lt 1.21")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
