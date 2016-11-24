# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-08.xml
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
 script_id(23673);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-08");
 script_cve_id("CVE-2006-5466");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-08
(RPM: Buffer overflow)


    Vladimir Mosgalin has reported that when processing certain packages,
    RPM incorrectly allocates memory for the packages, possibly causing a
    heap-based buffer overflow.
  
Impact

    An attacker could entice a user to open a specially crafted RPM package
    and execute code with the privileges of that user if certain locales
    are set.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All RPM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/rpm-4.4.6-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5466');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-08] RPM: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RPM: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/rpm", unaffected: make_list("ge 4.4.6-r3"), vulnerable: make_list("lt 4.4.6-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
