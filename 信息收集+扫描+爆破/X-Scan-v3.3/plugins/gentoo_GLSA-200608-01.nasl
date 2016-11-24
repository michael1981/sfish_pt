# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-01.xml
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
 script_id(22143);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-01");
 script_cve_id("CVE-2006-3747");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-01
(Apache: Off-by-one flaw in mod_rewrite)


    An off-by-one flaw has been found in Apache\'s mod_rewrite module by
    Mark Dowd of McAfee Avert Labs. This flaw is exploitable depending on
    the types of rewrite rules being used.
  
Impact

    A remote attacker could exploit the flaw to cause a Denial of Service
    or execution of arbitrary code. Note that Gentoo Linux is not
    vulnerable in the default configuration.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose www-servers/apache
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3747');
script_set_attribute(attribute: 'see_also', value: 'http://www.apache.org/dist/httpd/Announcement2.0.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.apache.org/dist/httpd/Announcement1.3.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-01] Apache: Off-by-one flaw in mod_rewrite');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Off-by-one flaw in mod_rewrite');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("rge 1.3.34-r14", "rge 1.3.37", "ge 2.0.58-r2"), vulnerable: make_list("lt 2.0.58-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
