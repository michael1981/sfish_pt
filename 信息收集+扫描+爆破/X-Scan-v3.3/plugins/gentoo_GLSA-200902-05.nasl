# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200902-05.xml
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
 script_id(35731);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200902-05");
 script_cve_id("CVE-2008-5905", "CVE-2008-5906");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200902-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200902-05
(KTorrent: Multiple vulnerabilitites)


    The web interface plugin does not restrict access to the torrent upload
    functionality (CVE-2008-5905) and does not sanitize request parameters
    properly (CVE-2008-5906) .
  
Impact

    A remote attacker could send specially crafted parameters to the web
    interface that would allow for arbitrary torrent uploads and remote
    code execution with the privileges of the KTorrent process.
  
Workaround

    Disabling the web interface plugin will prevent exploitation of both
    issues. Click "Plugins" in the configuration menu and uncheck the
    checkbox left of "WebInterface", then apply the changes.
  
');
script_set_attribute(attribute:'solution', value: '
    All KTorrent users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/ktorrent-2.2.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5905');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5906');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200902-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200902-05] KTorrent: Multiple vulnerabilitites');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KTorrent: Multiple vulnerabilitites');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/ktorrent", unaffected: make_list("ge 2.2.8"), vulnerable: make_list("lt 2.2.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
