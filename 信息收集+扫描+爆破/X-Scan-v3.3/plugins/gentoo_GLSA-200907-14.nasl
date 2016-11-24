# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-14.xml
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
 script_id(39868);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200907-14");
 script_cve_id("CVE-2009-1760");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-14
(Rasterbar libtorrent: Directory traversal)


    census reported a directory traversal vulnerability in
    src/torrent_info.cpp that can be triggered via .torrent files.
  
Impact

    A remote attacker could entice a user or automated system using
    Rasterbar libtorrent to load a specially crafted BitTorrent file to
    create or overwrite arbitrary files using dot dot sequences in
    filenames.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Rasterbar libtorrent users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-libs/rb_libtorrent-0.13-r1"
    All Deluge users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/deluge-1.1.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1760');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-14] Rasterbar libtorrent: Directory traversal');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Rasterbar libtorrent: Directory traversal');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/deluge", unaffected: make_list("ge 1.1.9"), vulnerable: make_list("lt 1.1.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-libs/rb_libtorrent", unaffected: make_list("ge 0.13-r1"), vulnerable: make_list("lt 0.13-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
