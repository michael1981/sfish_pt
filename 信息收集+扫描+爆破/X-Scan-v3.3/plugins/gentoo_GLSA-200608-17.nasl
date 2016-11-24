# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-17.xml
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
 script_id(22216);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200608-17");
 script_cve_id("CVE-2006-3376");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-17
(libwmf: Buffer overflow vulnerability)


    infamous41md discovered that libwmf fails to do proper bounds checking
    on the MaxRecordSize variable in the WMF file header. This could lead
    to an head-based buffer overflow.
  
Impact

    By enticing a user to open a specially crafted WMF file, a remote
    attacker could cause a heap-based buffer overflow and execute arbitrary
    code with the permissions of the user running the application that uses
    libwmf.
  
Workaround

    There is no known workaround for this issue.
  
');
script_set_attribute(attribute:'solution', value: '
    All libwmf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libwmf-0.2.8.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3376');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-17] libwmf: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libwmf: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libwmf", unaffected: make_list("ge 0.2.8.4"), vulnerable: make_list("lt 0.2.8.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
