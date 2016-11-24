# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-04.xml
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
 script_id(23669);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200611-04");
 script_cve_id("CVE-2006-5453", "CVE-2006-5454", "CVE-2006-5455");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-04
(Bugzilla: Multiple Vulnerabilities)


    The vulnerabilities identified in Bugzilla are as follows:
    Frederic Buclin and Gervase Markham discovered that input passed to
    various fields throughout Bugzilla were not properly sanitized before
    being sent back to users (CVE-2006-5453).
    Frederic Buclin and Josh "timeless" Soref discovered a bug when
    viewing attachments in diff mode that allows users not of the
    "insidergroup" to read attachment descriptions. Additionally, it was
    discovered that the "deadline" field is visible to users who do not
    belong to the "timetrackinggroup" when bugs are exported to XML
    (CVE-2006-5454).
    Gavin Shelley reported that Bugzilla allows certain operations to
    be performed via HTTP GET and HTTP POST requests without verifying
    those requests properly (CVE-2006-5455).
    Max Kanat-Alexander discovered that input passed to
    showdependencygraph.cgi is not properly sanitized before being returned
    to users (CVE-2006-5453).
  
Impact

    An attacker could inject scripts into the content loaded by a user\'s
    browser in order to have those scripts executed in a user\'s browser in
    the context of the site currently being viewed. This could include
    gaining access to privileged session information for the site being
    viewed. Additionally, a user could forge an HTTP request in order to
    create, modify, or delete bugs within a Bugzilla instance. Lastly, an
    unauthorized user could view sensitive information about bugs or bug
    attachments.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Bugzilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/bugzilla-2.18.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5453');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5454');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5455');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-04] Bugzilla: Multiple Vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bugzilla: Multiple Vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/bugzilla", unaffected: make_list("ge 2.18.6"), vulnerable: make_list("lt 2.18.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
