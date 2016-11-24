# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-04.xml
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
 script_id(25665);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200707-04");
 script_cve_id("CVE-2007-3508");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-04
(GNU C Library: Integer overflow)


    Tavis Ormandy of the Gentoo Linux Security Team discovered a flaw in
    the handling of the hardware capabilities mask by the dynamic loader.
    If a mask is specified with a high population count, an integer
    overflow could occur when allocating memory.
  
Impact

    As the hardware capabilities mask is honored by the dynamic loader
    during the execution of suid and sgid programs, in theory this
    vulnerability could result in the execution of arbitrary code with root
    privileges. This update is provided as a precaution against currently
    unknown attack vectors.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-libs/glibc-2.5-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3508');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-04] GNU C Library: Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNU C Library: Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-libs/glibc", arch: "x86", unaffected: make_list("ge 2.5-r4"), vulnerable: make_list("lt 2.5-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
