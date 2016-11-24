# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-07.xml
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
 script_id(39778);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200907-07");
 script_cve_id("CVE-2009-1438", "CVE-2009-1513");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-07
(ModPlug: User-assisted execution of arbitrary code)


    Two vulnerabilities have been reported in ModPlug:
    dummy reported an integer overflow in the CSoundFile::ReadMed()
    function when processing a MED file with a crafted song comment or song
    name, which triggers a heap-based buffer overflow (CVE-2009-1438).
    Manfred Tremmel and Stanislav Brabec reported a buffer overflow in the
    PATinst() function when processing a long instrument name
    (CVE-2009-1513).
    The GStreamer Bad plug-ins (gst-plugins-bad) before 0.10.11 built a
    vulnerable copy of ModPlug.
  
Impact

    A remote attacker could entice a user to read specially crafted files,
    possibly resulting in the execution of arbitrary code with the
    privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ModPlug users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libmodplug-0.8.7"
    gst-plugins-bad 0.10.11 and later versions do not include the ModPlug
    plug-in (it has been moved to media-plugins/gst-plugins-modplug). All
    gst-plugins-bad users should upgrade to the latest version and install
    media-plugins/gst-plugins-modplug:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gst-plugins-bad-0.10.11"
    # emerge --ask --verbose "media-plugins/gst-plugins-modplug"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1438');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1513');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-07] ModPlug: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ModPlug: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/gst-plugins-bad", unaffected: make_list("ge 0.10.11"), vulnerable: make_list("lt 0.10.11")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-libs/libmodplug", unaffected: make_list("ge 0.8.7"), vulnerable: make_list("lt 0.8.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
