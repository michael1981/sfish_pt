# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-16.xml
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
 script_id(20244);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200511-16");
 script_cve_id("CVE-2005-3349", "CVE-2005-3355");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-16
(GNUMP3d: Directory traversal and insecure temporary file creation)


    Ludwig Nussel from SUSE Linux has identified two vulnerabilities in
    GNUMP3d. GNUMP3d fails to properly check for the existence of
    /tmp/index.lok before writing to the file, allowing for local
    unauthorized access to files owned by the user running GNUMP3d. GNUMP3d
    also fails to properly validate the "theme" GET variable from CGI
    input, allowing for unauthorized file inclusion.
  
Impact

    An attacker could overwrite files owned by the user running GNUMP3d by
    symlinking /tmp/index.lok to the file targeted for overwrite. An
    attacker could also include arbitrary files by traversing up the
    directory tree (at most two times, i.e. "../..") with the "theme" GET
    variable.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GNUMP3d users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/gnump3d-2.9_pre7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3349');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3355');
script_set_attribute(attribute: 'see_also', value: 'http://www.gnu.org/software/gnump3d/ChangeLog');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-16] GNUMP3d: Directory traversal and insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GNUMP3d: Directory traversal and insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/gnump3d", unaffected: make_list("ge 2.9_pre7"), vulnerable: make_list("lt 2.9_pre7")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
