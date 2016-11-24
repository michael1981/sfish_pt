# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-32.xml
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
 script_id(15826);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200411-32");
 script_cve_id("CVE-2004-1315");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-32 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-32
(phpBB: Remote command execution)


    phpBB contains a vulnerability in the highlighting code and several
    vulnerabilities in the username handling code.
  
Impact

    An attacker can exploit the highlighting vulnerability to access the
    PHP exec() function without restriction, allowing them to run arbitrary
    commands with the rights of the web server user (for example the apache
    user). Furthermore, the username handling vulnerability might be abused
    to execute SQL statements on the phpBB database.
  
Workaround

    There is a one-line patch which will remediate the remote execution
    vulnerability.
    Locate the following block of code in viewtopic.php:
    //
    // Was a highlight request part of the URI?
    //
    $highlight_match = $highlight = \'\';
    if (isset($HTTP_GET_VARS[\'highlight\']))
    {
       // Split words and phrases
       $words = explode(\' \', trim(htmlspecialchars(urldecode($HTTP_GET_VARS[\'highlight\']))));
       for($i = 0; $i < sizeof($words); $i++)
       {
    Replace with the following:
    //
    // Was a highlight request part of the URI?
    //
    $highlight_match = $highlight = \'\';
    if (isset($HTTP_GET_VARS[\'highlight\']))
    {
       // Split words and phrases
       $words = explode(\' \', trim(htmlspecialchars($HTTP_GET_VARS[\'highlight\'])));
       for($i = 0; $i < sizeof($words); $i++)
       {
  
');
script_set_attribute(attribute:'solution', value: '
    All phpBB users should upgrade to the latest version to fix all known
    vulnerabilities:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpbb-2.0.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpbb.com/phpBB/viewtopic.php?t=240513');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1315');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-32.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-32] phpBB: Remote command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Remote command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpbb", unaffected: make_list("ge 2.0.11"), vulnerable: make_list("lt 2.0.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
