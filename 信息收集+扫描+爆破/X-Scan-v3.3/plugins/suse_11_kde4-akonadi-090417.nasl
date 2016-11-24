
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(41409);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  kde4-akonadi (2009-04-17)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kde4-akonadi");
 script_set_attribute(attribute: "description", value: "This kdepim4 and kdepimlibs4 update fixes lots of bugs and
one security issue:

KMail 4.1.x executes links in mail without confirmation.
(no cve assigned yet)

It also fixes lots of non-security bugs:

kdepim4:
  - kdepim: make sure we initially create items for
    subresources
  - kdepim: fix autocompletion shortcut error
  - kdepim: reduce linkage
  - akregator: fix copy text from article view widget
    (kde#168865)
  - akregator: fix saving articlelistview settings
    (kde#176262,bnc#430825)
  - akregator: improve prev/next unread article behavior
    when a filter is set (kde#138935)
  - gpgme: Fix persistent progress dialogs for GPG key ops
    (kde#169563)
  - kaddressbook: fix help anchors
  - kaddressbook: set department and org fields on vcard
    export
  - kaddressbook: Fix LDIF import for files with windows
    linebreaks
  - kalarm: fix translation not loaded
  - kalarm: correctly handle failure to create alarm
    resource
  - kalarm: Copying alarm to KOrganizer fails when embedded
    in Kontact (kde#176759)
  - kalarm: Fix kalarmautostart crash on logout
  - kalarm: fix click on system tray icon not showing main
    window
  - kalarm: disabled from enabled alarm colour when
    highlighted in alarm list
  - kalarm: UI fixes
  - kalarm: signal when work hours change
  - kalarm: fix command alarms (kde#175623)
  - kalarm: Fix toolbar settings being lost
  - kalarm: Fix crash if activated again while restoring
    from previous session
  - kalarm: update change log
  - kalarm: correct system tray icon parent
  - kalarm: show idle time on correct virtual desktop
    (kde#153442,kde#174346)
  - kalarm: ensure alarms shown above full-screen windows
  - kalarm: Fix invalid alarm remaining in calendar on
    failure
  - kjots: fix paste of richtext and tabs becoming spaces
    bugs (kde#160600,kde#175100)
  - kmail: fix loss of configured receiving accounts on
    exit with wallet dialog open (kde#169166)
  - kmail: do not execute executables when clicking a link,
    and solve dangling kmmsgbase pointer crash
    (kde#179765,bnc#490696)
  - kmail: fix crash when syncing imap flags (kde#106030)
  - kmail: detect urgent X-Priority correctly
  - kmail: fix opening zip attachments
  - kmail: don't show unconfigurable shortcuts in dialog
  - kmail: fix added subfolders not appearing in the folder
    selection dialog
  - kmail: configure dialog UI fixes
  - kmail: display receiving accounts correctly in config
  - kmail: unread mail layout bug (bug#174304)
  - kmail: don't force duplicate add to addressbook
    (kde#174332)
  - kmail: remove deprecated spamassassin flag (kde#140032)
  - kmail: update detected encoding on inserting file in
    composer (kde#88781)
  - kmail: fix unreactive encoding change dialog
    (kde#149309,kde#145163)
  - kmail: update detected encoding on inserting file in
    composer (kde#88781)
  - kmail: fix out of range in parsing mail bug
  - kmail: various encoding fixes (kde#64815)
  - kmail: remove spurious assert
  - kmail: sieve dialog fixes
  - kmail: missing i18n
  - kmail: Fix the 'open in addressbook' action
  - kmail: attachments check fix
  - kmail: Fix spacing in Configure
  - kmail: fix inline-forwarding of messages with
    attachments. (kde#178128,kde#146921)
  - kmail: don't allow attachment deletion/editing in
    read-only folders (kolab#3324)
  - kmail: fix crash when clicking on one of the invitation
    action links
  - kmail: fix inline forwarding of multipart/mixed messages
  - kmail: fix crashing in templates (kde#178038)
  - knode: fix rules editor crash and saving and loading of
    scoring rules (kde:170030,kde:175045)
  - knode: fix incorrect charset header (kde:169411)
  - knode: safety checks
  - knotes: various crash fixes
  - knotes: don't exit when the last window is closed
    (kde#153244)
  - kontact: fix help anchors
  - kontact: fix crash on opening configure dialog
    (kde#174707)
  - korganizer: fix task filtering (kde#171205)
  - korganizer: public holidays for Chile
  - korganizer: public holidays for Jamaica
  - korganizer: fix crash when deleting categories with
    deep subcategories (kde#153740)
  - korganizer: fix Russian holidays
  - korganizer: allow to change my status even if I'm the
    organizer of this event (kolab#3084)
  - korganizer: Fix crashes on saving new calendar
  - korganizer: correct Norwegian public holidays
  - korganizer: calendar scroll widget fixes
  - korganizer: navigator bar menu fixes
  - korganizer: navigatorbar - fix selectMonth() to emit
    the correct month index
  - korganizer: navigatorbar - layout cleanup
  - korganizer: indicate when subresources are present
  - korganizer: fix missing RTL text in monthviews
  - korganizer: potential setNoActionCursor crash fix
  - korganizer: navigatorbar - fix jumping labels
  - korganizer: navigatorbar - fix crash on exit
  - korganizer: fix alignment of day labels to main matrix
  - korganizer: make do not show to-dos in monthview work
  - korganizer: fix crash on removing attendees (kde#172354)
  - korganizer: fix cancelling imip send
  - korganizer: fix print crashing (kde#160260)
  - korganizer: fix print default year
  - korganizer: fix printing generally
  - korganizer: fix printing UTC incidences (kde)
  - korganizer: fix month view doesnt react to key and
    mouse events (kde#175814)
  - korganizer: make paste work on actual selection
    (kde#175814,kde#132863)
  - korganizer: pasting fix
 - korganizer: fix sorting todos
  - korganizer: menu fixes
  - korganizer: backports to help make Paste work
  - korganizer: type-ahead event creation ignores ctrl keys
  - korganizer: robustness work in synchronous address book
    loading
  - korganizer: paint the all-day item headers
  - korganizer: initialise special dates UI correctly
  - korganizer: disable the configuration area for
    deselected plugins
  - korganizer: hide redundant configure plugin button
  - korganizer: fix agendaview configuration
  - korganizer: ensure agendaview decoration is selected
  - korganizer: fix to-do copying
  - korganizer: todo rich text speedup
  - korganizer: fix what's next view todo links
  - korganizer: fix event duplication when moving events
    with the mouse.
  - korganizer: fix duplicate default resources (bnc#116351)
  - korganizer: fix tab order
  - korganizer: fix performance problems on updateEvents()
  - korganizer: fix new journal is set to date of the first
    day of the week/month (kde#170634)
  - korganizer: fix slow switching calendar views
    (kde#170993)
  - korganizer: maintain selected day on view change
  - korganizer: fix performance problems with month
    switching (kde#166771)
  - korganizer: don't load decoration plugins multiple times
  - korganizer: an attempt at fixing the dreaded crash in
    paintEvent().
  - korganizer: fixes in pasting
  - korganizer: don't lose last day on setting recurring
    events
  - korganizer: updated Slovenian holidays
  - korganizer: avoid assert when adding attachments
  - kresources: blog - remove non-working LiveJournal
    support
  - kresources: birthdays - complete load sequence
  - kresources: birthdays - fix alarms
  - kresources: Write subresource state changes immediately
    (kolab#3314)
  - kresources: groupwise -  fixes to warn on trying to set
    up dud local<->remote id mappings
  - ktimetracker: fix crash when deleting the last task
    (kde:173543)

kdepimlibs4:
  - fixes a crash on korgac startup triggered when parsing
    the timezoneId from a null string
  - libical safety fix
  - memleak in Generic kmime header
  - test before delete[] is not needed
  - fix memleak in knode
  - fix the kio_sieve related klauncher crashes
  - return better errors for gpgme write failures and
    missing passphrases
  - Fix signing of multiple uids (!= all, though) at the
    same time
  - Print the nextState() call also in the error case
  - gpgme: Fix 'General Error' returned when trying to sign
    an already signed UID again with the same key.
  - gpgme: use better error codes
  - gpgme: Treat GPGME_STATUS_{KEY,SIG}EXPIRED as errors,
    too.
  - gpgme: Add missing gpg_error() call (to set the correct
    source of the error)
  - kblog: fix broken tagging
  - kblog: GData tagging fix
  - fix sending mail fails due to spurious newline in
    server name configuration (kde#175892)
  - fix korganizer crash with akonadi resources (kde#175971)
  - remove use of isNull in icalformat
  - properly initialize kcal::attachment ctor
  - kcal: fix spurious error on empty alarm trigger
  - kcal: inline attachment fixes
  - kcal: crash fixes
  - kldap: crash bug fix (kde#174381)
  - Fix LDAP using simple authentication (kde#163319)
  - ldap: Quote CN parameters correctly. (kolab#3281)
  - update reference test files
  - merge updated testcase runner
  - use .shell versions of tests
  - remove mistaken reference files
  - fix a backporting boo-boo
  - kcal: fix an ical date interpretation bug
  - Fix a crash when using egroupware.
  - Fix a crash in KOrganizer when the addressbook contains
    a LDAP resource.
  - Fixes an assert crash when unloading and then loading a
    vCal resource
  - Fix high traffic rss feed fetches
  - Fix for improperly formatted mailto: links in the
    KOrganizer eventviewer.
  - fixcrash if data() returns null (CID:3969)
  - Fix sieve with dovecot servers
  - Fix parsing of time string to be more conforming to ISO
    8601
  - kcal: Fix iCal export due to wrongly discarded last
    byte (porting bug) (kde#182224)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kde4-akonadi");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=490696");
script_end_attributes();

script_summary(english: "Check for the kde4-akonadi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kde4-akonadi-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-akregator-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kaddressbook-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kalarm-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kjots-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kmail-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-knode-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-knotes-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kontact-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-korganizer-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-ktimetracker-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-ktnef-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepim4-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepim4-wizards-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepimlibs4-4.1.3-9.28.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libakonadi4-4.1.3-9.28.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libkdepim4-4.1.3-9.14.6", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libkdepimlibs4-4.1.3-9.28.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-akregator-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kaddressbook-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kalarm-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kjots-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kmail-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-knode-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-knotes-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-kontact-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-korganizer-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-ktimetracker-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kde4-ktnef-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepim4-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepim4-wizards-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kdepimlibs4-4.1.3-9.28.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libakonadi4-4.1.3-9.28.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libkdepim4-4.1.3-9.14.6", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libkdepimlibs4-4.1.3-9.28.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
