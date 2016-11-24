# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-24.xml
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
 script_id(14779);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-24");
 script_cve_id("CVE-2004-0801");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-24
(Foomatic: Arbitrary command execution in foomatic-rip filter)


    There is a vulnerability in the foomatic-filters package. This
    vulnerability is due to insufficient checking of command-line parameters
    and environment variables in the foomatic-rip filter.
  
Impact

    This vulnerability may allow both local and remote attackers to execute
    arbitrary commands on the print server with the permissions of the spooler
    (oftentimes the "lp" user).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All foomatic users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-print/foomatic-3.0.2"
    # emerge ">=net-print/foomatic-3.0.2"
    PLEASE NOTE: You should update foomatic, instead of foomatic-filters. This
    will help to ensure that all other foomatic components remain functional.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.linuxprinting.org/pipermail/foomatic-devel/2004q3/001996.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:094');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0801');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-24] Foomatic: Arbitrary command execution in foomatic-rip filter');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Foomatic: Arbitrary command execution in foomatic-rip filter');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/foomatic", unaffected: make_list("ge 3.0.2"), vulnerable: make_list("le 3.0.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-print/foomatic-filters", unaffected: make_list("ge 3.0.2"), vulnerable: make_list("le 3.0.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
