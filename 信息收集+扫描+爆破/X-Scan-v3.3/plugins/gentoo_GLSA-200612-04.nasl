# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-04.xml
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
 script_id(23856);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200612-04");
 script_cve_id("CVE-2006-4192");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-04
(ModPlug: Multiple buffer overflows)


    Luigi Auriemma has reported various boundary errors in load_it.cpp and
    a boundary error in the "CSoundFile::ReadSample()" function in
    sndfile.cpp.
  
Impact

    A remote attacker can entice a user to read crafted modules or ITP
    files, which may trigger a buffer overflow resulting in the execution
    of arbitrary code with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ModPlug users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libmodplug-0.8-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4192');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-04] ModPlug: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ModPlug: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/libmodplug", unaffected: make_list("ge 0.8-r1"), vulnerable: make_list("lt 0.8-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
