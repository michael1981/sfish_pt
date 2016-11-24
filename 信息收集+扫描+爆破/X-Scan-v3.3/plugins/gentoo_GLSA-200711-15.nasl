# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-15.xml
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
 script_id(28198);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-15");
 script_cve_id("CVE-2007-4619");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-15
(FLAC: Buffer overflow)


    Sean de Regge reported multiple integer overflows when processing FLAC
    media files that could lead to improper memory allocations resulting in
    heap-based buffer overflows.
  
Impact

    A remote attacker could entice a user to open a specially crafted FLAC
    file or network stream with an application using FLAC. This might lead
    to the execution of arbitrary code with privileges of the user playing
    the file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FLAC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/flac-1.2.1-r1"
    You should also run revdep-rebuild to rebuild any packages that depend
    on older versions of FLAC:
    # revdep-rebuild --library=libFLAC.*
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4619');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-15] FLAC: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FLAC: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/flac", unaffected: make_list("ge 1.2.1-r1"), vulnerable: make_list("lt 1.2.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
