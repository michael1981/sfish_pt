# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-14.xml
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
 script_id(22929);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200610-14");
 script_cve_id("CVE-2006-4812");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200610-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200610-14
(PHP: Integer overflow)


    A flaw in the PHP memory handling routines allows an unserialize() call
    to be executed on non-allocated memory due to a previous integer
    overflow.
  
Impact

    An attacker could execute arbitrary code with the rights of the web
    server user or the user running a vulnerable PHP script.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP 5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.1.6-r6"
    All PHP 4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-4.4.4-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4812');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200610-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200610-14] PHP: Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("rge 4.4.4-r6", "rge 4.4.6", "rge 4.4.7", "rge 4.4.8_pre20070816", "ge 5.1.6-r6"), vulnerable: make_list("lt 5.1.6-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
