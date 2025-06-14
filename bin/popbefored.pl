#!/usr/bin/perl
#
# popbefored.pl: Support daemon for POP Before SMTP by chacha.
#
use 5.028;
use strict;
use warnings;
use DB_File;
use Fcntl       qw(:flock O_RDWR O_CREAT);
use POSIX       qw(setsid);
use Time::Local qw(timelocal);
use IO::Handle;    # Required for autoflush
use GetFqdnWlc qw(get_fqdn_wlc);

# Define program version
my $version = '0.111';

# Configuration variables
my $logging    = 1;                               # 1: Enable self-logging. 0: Disable self-logging.
my $mail_log   = '/var/log/mail.log';             # Mail log file containing POP entries.
my $stats_file = '/var/local/popbefore.db';       # Main POP before SMTP database.
my $plast_file = '/var/local/popbeforelast.db';   # Database for last POP authentication times.
my $plast_exc_file =
  '/var/local/popbeforelast-exc.db';    # Database for last POP authentication times (exceptions).
my $mypid   = '/var/run/popbefored.pid';        # PID file for the daemon.
my $mylog   = '/var/log/popbefore.log';         # Log file for the daemon if $logging is enabled.
my $out_map = '/etc/postfix/maps/popbefore';    # Postfix map file to be updated.
my $expire  = 30 * 60;    # Expiration time for a POP authentication entry in seconds. (30 minutes)
my $freq    = 3;          # Check for expired entries every ($expire / $freq) period.
my $DAEMON  = 1;          # Run as a daemon process (1: Yes, 0: No).
my $DOVECOT = 1;          # Enable Dovecot log parsing support.
my $RFC5424 = 1;          # Enable RFC 5424 log format parsing (for Dovecot).

# Global file handles and database objects
my $mlog_ino;             # Inode number of the mail log file when opened
my ($fh_log, $fh_mlog);

# Month to number mapping for log parsing
#<<< format skipping
my %Month = (
    'Jan' => 0, 'Feb' => 1, 'Mar' => 2, 'Apr' => 3,
    'May' => 4, 'Jun' => 5, 'Jul' => 6, 'Aug' => 7,
    'Sep' => 8, 'Oct' => 9, 'Nov' => 10, 'Dec' => 11
);
#>>>

# perlcritic settings
##  no critic (RegularExpressions::RequireExtendedFormatting)
##  no critic (ErrorHandling::RequireCarping)

# Flag to indicate HUP signal received
my $hup_received = 0;

# Signal handlers
local $SIG{'HUP'}  = \&hup_handler;
local $SIG{'INT'}  = \&exit_handler;
local $SIG{'QUIT'} = \&exit_handler;
local $SIG{'TERM'} = \&exit_handler;    # for more robust shutdown

##
# @brief HUP signal handler. Sets a flag to re-open log files and re-initialize state.
#
sub hup_handler {
    $hup_received = 1;
    return;
}

##
# @brief Exit signal handler. Ensures databases and file handles are closed cleanly before exiting.
#
sub exit_handler {
    close_all();
    exit 0;    # Exit cleanly
}

##
# @brief Initializes daemon process. Forks and detaches from controlling terminal.
#
sub daemonize {
    return unless $DAEMON;

    # Fork and exit parent process
    fork and exit 0;

    # Detach from controlling terminal
    setsid();

    # Write PID to file
    open(my $fh_pid, '>', $mypid) or die "Cannot open PID file: $mypid [$!]";
    print $fh_pid $$;
    close($fh_pid);

    ## no critic (Variables::RequireLocalizedPunctuationVars)
    my $a = $0;
    $0 = $a;

    return;
}

##
# @brief Opens main log files ($mylog and $mail_log).
#        Also records the inode of $mail_log for rotation detection.
#
sub open_logs {
    if ($logging) {
        ## no critic (InputOutput::RequireBriefOpen)
        open($fh_log, '>>', $mylog) || die "Cannot open file: $mylog [$!]";
        $fh_log->autoflush(1);    # Enable autoflush for immediate writes
        print_log(time, "Start popbefored (v$version). expire = $expire [sec]");
    }
    ## no critic (InputOutput::RequireBriefOpen)
    open($fh_mlog, '<', $mail_log) || die "Cannot open file: $mail_log [$!]";
    ## my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks)
    ##     = stat($filename);
    $mlog_ino = (stat($mail_log))[1];    # Store inode for rotation detection
    return;
}

##
# @brief Closes all open log file handles.
#
sub close_logs {
    close($fh_mlog) if defined $fh_mlog;
    undef $fh_mlog;
    close($fh_log) if defined $fh_log;
    undef $fh_log;
    return;
}

##
# @brief Opens and ties DB_File databases, applying exclusive locks.
# @param \%stats_ref A reference to the %stats hash.
# @param \%plast_ref A reference to the %plast hash.
# @param \%plast_exc_ref A reference to the %plast_exc hash.
# @return A list of file handles for the flock files.
#
sub open_databases {
    my ($stats_ref, $plast_ref, $plast_exc_ref) = @_;

    my @flock_paths = ("$stats_file.flock", "$plast_file.flock", "$plast_exc_file.flock");
    my @db_files    = ($stats_file, $plast_file, $plast_exc_file);
    my @tied_hashes = ($stats_ref,  $plast_ref,  $plast_exc_ref);

    my @flock_fhs;    # Store file handles for flock files

    for my $i (0 .. $#flock_paths) {
        my $flock_path = $flock_paths[$i];
        my $db_file    = $db_files[$i];
        my $tied_hash  = $tied_hashes[$i];

        # Open flock file and acquire exclusive lock
        ## no critic (InputOutput::RequireBriefOpen)
        open(my $flock_fh, '>>', $flock_path)
          or die "Cannot open flock file: $flock_path [$!]";
        flock($flock_fh, LOCK_EX)
          or die "Cannot get exclusive flock on file: $flock_path [$!]";

        # Tie the DBM hash
        tie(%{$tied_hash}, "DB_File", $db_file, O_CREAT | O_RDWR, 0o666, $DB_HASH)
          || die "Cannot open db file: $db_file [$!]";

        push @flock_fhs, $flock_fh;
    }
    return @flock_fhs;
}

##
# @brief Closes and unties DB_File databases, releasing locks.
# @param \%stats_ref A reference to the %stats hash.
# @param \%plast_ref A reference to the %plast hash.
# @param \%plast_exc_ref A reference to the %plast_exc hash.
# @param @flock_fhs A list of file handles for the flock files to close.
#
sub close_databases {
    my ($stats_ref, $plast_ref, $plast_exc_ref, @flock_fhs) = @_;

    # Untie hashes first
    untie(%{$stats_ref})     if tied %{$stats_ref};
    untie(%{$plast_ref})     if tied %{$plast_ref};
    untie(%{$plast_exc_ref}) if tied %{$plast_exc_ref};

    # Close flock file handles
    for my $fh (@flock_fhs) {
        close($fh) if defined $fh;
    }
    return;
}

##
# @brief Synchronizes DB_File hashes to disk.
# @param \%stats_ref A reference to the %stats hash.
# @param \%plast_ref A reference to the %plast hash.
# @param \%plast_exc_ref A reference to the %plast_exc hash.
#
sub sync_databases {
    my ($stats_ref, $plast_ref, $plast_exc_ref) = @_;
    tied(%{$stats_ref})->sync     if tied %{$stats_ref};
    tied(%{$plast_ref})->sync     if tied %{$plast_ref};
    tied(%{$plast_exc_ref})->sync if tied %{$plast_exc_ref};
    return;
}

##
# @brief Opens and ties DB_File databases, applying exclusive locks.
# @param \%stats_ref A reference to the %stats hash.
# @return A list of file handles for the flock files.
#
sub open_database_stats {
    my ($stats_ref) = @_;

    my $flock_path = "$stats_file.flock";
    my $db_file    = $stats_file;
    my $tied_hash  = $stats_ref;

    # Open flock file and acquire exclusive lock
    ## no critic (InputOutput::RequireBriefOpen)
    open(my $flock_fh, '>>', $flock_path)
      or die "Cannot open flock file: $flock_path [$!]";
    flock($flock_fh, LOCK_EX)
      or die "Cannot get exclusive flock on file: $flock_path [$!]";

    # Tie the DBM hash
    tie(%{$tied_hash}, "DB_File", $db_file, O_CREAT | O_RDWR, 0o666, $DB_HASH)
      || die "Cannot open db file: $db_file [$!]";

    return $flock_fh;
}

##
# @brief Closes and unties DB_File databases, releasing locks.
# @param \%stats_ref A reference to the %stats hash.
# @param @flock_fhs A list of file handles for the flock files to close.
#
sub close_database_stats {
    my ($stats_ref, $flock_fh) = @_;
    ## Untie hashes first
    untie(%{$stats_ref}) if tied %{$stats_ref};
    ## Close flock file handles
    close($flock_fh) if defined $flock_fh;
    return;
}

##
# @brief Synchronizes DB_File hashes to disk.
# @param \%stats_ref A reference to the %stats hash.
#
sub sync_database_stats {
    my ($stats_ref) = @_;
    tied(%{$stats_ref})->sync if tied %{$stats_ref};
    return;
}

##
# @brief Closes all global open resources (logs) and cleans up PID file.
#         DBMs are managed within the functions that use them.
#
sub close_all_fhs {
    close_logs();
    unlink $mypid if -f $mypid;    # Remove PID file on exit
    return;
}

##
# @brief Main loop of the daemon. Handles log processing, expiration, and map updates.
#
sub main_loop {
    my $now;
    my $map_needs_update = 0;    # Flag to indicate if the Postfix map needs to be rebuilt

    # Initial setup
    daemonize();

    for (; ;) {                  # Outer loop for handling log rotation and HUP signals
        $hup_received = 0;       # Reset HUP flag for the new cycle
        open_logs();
        $now = time;

        # Initial scan of the mail log, opening databases only for this operation
        $map_needs_update += process_initial_mail_log_scan($now);

        if ($map_needs_update) {
            ## Create/update map based on initial scan
            update_postfix_map();
            $map_needs_update = 0;
        }

        my $next_expire_check_time = $now + ($expire / $freq);

        for (; ;) {    # Inner loop for continuous monitoring and periodic tasks
            $now = time;
            ## Read new entries from the log
            $map_needs_update += read_new_mail_log_entries($now);
            if ($now >= $next_expire_check_time) {
                $map_needs_update += expire_old_entries($now);
                $next_expire_check_time = $now + ($expire / $freq);
                ## $next_expire_check_time += ($expire / $freq);
            }
            if ($map_needs_update) {
                ## Update map after expiration (if changes occurred)
                update_postfix_map();
                $map_needs_update = 0;
            }

            sleep(1);    # Sleep for 1 second to reduce CPU usage

            # Break inner loop if mail log file has changed (e.g., rotated) or HUP signal received
            last if is_mail_log_rotated();
            last if $hup_received;
        }
        close_logs();    # Close logs before re-opening in the next outer loop iteration
    }
    return;
}

##
# @brief Checks if the mail log file has been rotated by comparing inode numbers.
# @return 1 if rotated, 0 otherwise.
#
sub is_mail_log_rotated {
    my $current_ino = (stat($mail_log))[1];
    if ($current_ino != $mlog_ino) {
        print_log(time, "Mail log file rotated. Re-opening.");
        return 1;
    }
    return 0;
}

##
# @brief Processes the entire mail log file to populate initial statistics.
#        This is typically done on daemon start or when a HUP signal is received.
# @param $now Current Unix timestamp.
# @return 1 if the map needs an update, 0 otherwise.
#
sub process_initial_mail_log_scan {
    my ($now) = @_;
    my ($sec0, $min0, $hour0, $mday0, $mon0, $year0) = localtime($now);
    my $expiration_threshold = $now - $expire;
    my $map_needs_update     = 0;
    my (%stats, %plast, %plast_exc);    # Declare local hashes for DB_File
    my $fqdn = GetFqdnWlc->new();

    print_log(time, "Scanning $mail_log for existing entries.");

    my @flock_fhs = open_databases(\%stats, \%plast, \%plast_exc);

    # Ensure we are at the beginning of the file for a full scan
    seek($fh_mlog, 0, 0);

    while (my $line = <$fh_mlog>) {
        my ($success, $log_time, $formatted_time, $user, $host, $ip, $protocol, $is_exception) =
          parse_log_line($line, $mon0, $year0, $fqdn);
        next unless $success;

        my $data = "$log_time^$formatted_time^$host^$ip^$protocol";
        if ($log_time > $expiration_threshold) {
            my $key = $ip || $host;    # Prefer IP if available
            $stats{$key} = $data;
        }
        unless ($is_exception) {
            $plast{$user} = $data;
        }
        else {
            $plast_exc{$user} = $data;
        }

        # Indicate that the map needs an update after initial scan
        $map_needs_update = 1;
    }
    sync_databases(\%stats, \%plast, \%plast_exc);
    close_databases(\%stats, \%plast, \%plast_exc, @flock_fhs);
    return $map_needs_update;
}

##
# @brief Reads and processes new entries from the mail log file.
#        This function resumes reading from where it left off (due to seek 0,1).
# @param $now Current Unix timestamp.
# @return 1 if the map needs an update, 0 otherwise.
#
sub read_new_mail_log_entries {
    my ($now) = @_;
    my ($sec0, $min0, $hour0, $mday0, $mon0, $year0) = localtime($now);
    my $map_needs_update = 0;
    my $fqdn             = GetFqdnWlc->new();
    my (%stats, %plast, %plast_exc);    # Declare local hashes for DB_File

    my $is_opened = 0;
    my @flock_fhs;
    ##
    ## Seek to the current end of the file before reading new lines.
    ## This is effectively what `seek($fh_mlog, 0, 1)` does when used inside a loop.
    ## This simply clears the EOF flag.
    seek($fh_mlog, 0, 1);

    while (my $line = <$fh_mlog>) {
        my ($success, $log_time, $formatted_time, $user, $host, $ip, $protocol, $is_exception) =
          parse_log_line($line, $mon0, $year0, $fqdn);
        next unless $success;
        unless ($is_opened) {
            @flock_fhs = open_databases(\%stats, \%plast, \%plast_exc);
            $is_opened = 1;
        }

        my $key            = $ip || $host;
        my $status_message = ($stats{$key}) ? 'upd' : 'new';

        my $data = "$log_time^$formatted_time^$host^$ip^$protocol";

        $stats{$key} = $data;
        unless ($is_exception) {
            $plast{$user} = $data;
        }
        else {
            $plast_exc{$user} = $data;
        }

        my $s = sprintf("%s %-15s [%s] %s %d", $status_message, $host, $ip, $user, $log_time);
        print_log($log_time, $s) if $logging;

        if ($status_message eq 'new') {
            $map_needs_update = 1;    # Mark for immediate map update
        }
    }
    if ($is_opened) {
        sync_databases(\%stats, \%plast, \%plast_exc);
        close_databases(\%stats, \%plast, \%plast_exc, @flock_fhs);
    }
    return $map_needs_update;
}

##
# @brief Parses a single line from the mail log, extracting relevant information.
# @param $line The log line to parse.
# @param $current_month The current month (0-11) for year inference.
# @param $current_year The current year (since 1900) for year inference.
# @param $fqdn GetFqdnWlc object for reverse DNS lookup.
# @return A list containing (success_flag, ptime, stime, user, host, ip, protocol, exception_flag).
#
sub parse_log_line {
    my ($m,   $mon0, $year0, $fqdn) = @_;
    my ($sec, $min,  $hour,  $mday, $mon, $user, $host, $ip, $prot);
    my ($exc, $r);

    if ($DOVECOT) {
        ($r, $sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot) =
          parse_log_line_dovecot($m, $mon0, $year0, $fqdn);
        return (0) unless ($r);
    }
    else {
        ($r, $sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot) =
          parse_log_line_old_ipop3d($m, $mon0, $year0);
        return (0) unless ($r);
    }

    # Custom exception logic for certain IPs/hostnames (e.g., common mail clients, cloud services)
    $exc = 0;    # Initialize exception flag
    if ($prot eq 'imap' && $host eq '' && $ip ne '') {

        # Microsoft Corp's address ranges (common for Outlook, Exchange Online)
        if (   $ip =~ /^40\.9[6-9]\.\d+\.\d+$/
            || $ip =~ /^40\.10[0-9]\.\d+\.\d+$/
            || $ip =~ /^40\.11[0-1]\.\d+\.\d+$/
            || $ip =~ /^52\.9[6-9]\.\d+\.\d+$/)
        {
            $exc = 1;
        }
    }
    elsif ($prot eq 'pop3') {
        if ($host ne '') {

            # Amazon EC2 (ap-northeast-1 region)
            ## no critic (RegularExpressions::ProhibitComplexRegexes)
            if ($host =~ /^ec2-\d+-\d+-\d+-\d+\.ap-northeast-1\.compute\.amazonaws\.com$/) {
                $exc = 1;
            }

            # DataPacket
            if ($host =~ /^unn-\d+-\d+-\d+-\d+\.datapacket\.com$/) {
                $exc = 1;
            }

            # spmode (Japanese mobile carrier, NTT Docomo)
            if ($host =~ /^sp\d+-\d+-\d+-\d+\..*\.spmode\.ne\.jp$/) {
                $exc = 1;
            }
        }
        else {    # If hostname is empty, rely on IP
                  # NortonLifeLock (Symantec)
            if ($ip =~ /^199\.85\.125\.\d+$/) {
                $exc = 1;
            }
        }
    }

    # Infer year for log entries that might span across year boundaries (e.g., Dec log read in Jan)
    my $year = $year0;
    $year-- if ($mon > $mon0);

    my $parsed_time = timelocal($sec, $min, $hour, $mday, $mon, $year);
    my $formatted_time =
      sprintf("%04d/%02d/%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);

    return (1, $parsed_time, $formatted_time, $user, $host, $ip, $prot, $exc);
}

sub parse_log_line_dovecot {
    my ($m, $mon0, $year0, $fqdn) = @_;
    my ($sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot, $exc);
    if ($RFC5424) {
        ## RFC 5424 format example:
        ## 2024-10-22T20:00:01.276189+09:00 exp1 dovecot: pop3-login: Login: user=<tony>, method=PLAIN, rip=61.197.49.146, lip=172.17.0.131, mpid=3147, TLS, session=<3EQSIZLnDsM9xTGS>
        ## no critic (RegularExpressions::ProhibitComplexRegexes)
        if ($m =~
/^\d+-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.\d+\S+ \S+ dovecot: (pop3|imap)-login: (\w+): user=<([^>]+)>, method=\S+, rip=([0-9.]+), lip=.*$/
          )
        {
            return (0)
              unless ($7 eq 'Login' || $7 eq 'Auth');  # Ensure it's a login or authentication event
            #<<< format skipping
            $mon  = $1 - 1; # Month is 1-indexed in log, convert to 0-indexed
            $mday = $2;
            $hour = $3; $min = $4; $sec = $5;
            $user = $8; # User is captured from <user> tag
            $ip   = $9; # IP address is captured from rip=
            $prot = $6; # Protocol (pop3 or imap)
            $host = ''; # Will be resolved via reverse DNS if needed
            #>>>
        }
        else {
            return (0);
        }
    }
    else {
        ## Standard Dovecot format example:
        ## Sep 1 08:48:09 exp1 dovecot: pop3-login: Login: user=<tony>, method=PLAIN, rip=61.197.49.146, lip=172.17.0.131, mpid=3147, TLS, session=<3EQSIZLnDsM9xTGS>
        ## no critic (RegularExpressions::ProhibitComplexRegexes)
        if ($m =~
/^(\w+)\s+(\d+) (\d+):(\d+):(\d+) \S+ dovecot: (pop3|imap)-login: (\w+): user=<([^>]+)>, method=\S+, rip=([0-9.]+), lip=.*$/
          )
        {
            return (0) unless ($7 eq 'Login' || $7 eq 'Auth');
            #<<< format skipping
            $mon  = $Month{$1};
            $mday = $2;
            $hour = $3; $min = $4; $sec = $5;
            $user = $8;
            $ip   = $9;
            $prot = $6;
            $host = '';
            #>>>
        }
        else {
            return (0);
        }
    }

    # Attempt reverse DNS lookup for IP if available
    if ($ip) {
        ##my $resolved_host =
        ##  `host -t PTR $ip 2>/dev/null`;    # -tn PTR specifies PTR record lookup
        ##if ($resolved_host =~ /^\S+\.in-addr\.arpa domain name pointer (\S+)\.$/) {
        ##    $host = $1;
        ##}
        my $s = $fqdn->get_fqdn_wlc($ip);
        $host = $s if ($s);
    }
    return (1, $sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot);
}

sub parse_log_line_old_ipop3d {
    my ($m, $mon0, $year0) = @_;
    my ($sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot, $exc);

    ## Old ipop3d format example:
    ## Nov 25 19:58:27 exp1 ipop3d[20461]: Login user=tony host=YahooBB218.bbtec.net
    ## Oct 15 09:09:43 exp1 ipop3d[14211]: Login user=tony host=[202.32.124.66] nmsgs=5/5
    ## Dec  1 10:04:13 exp1 ipop3d[21869]: Login user=tony host=ns1.example.com [61.209.254.2] nmsgs=0/0
    ## no critic (RegularExpressions::ProhibitComplexRegexes)
    if ($m =~ /^(\w+)\s+(\d+) (\d+):(\d+):(\d+) \S+ ipop3d\[\d+\]: (\w+) user=(\S+) host=(.*)$/) {
        return (0) unless ($6 eq 'Login' || $6 eq 'Auth');
        #<<< format skipping
        $mon  = $Month{$1}; $mday = $2;
        $hour = $3; $min  = $4; $sec  = $5;
        $user = $7;
        #>>>

        my $raw_host_field = $8;
        $ip   = '';
        $prot = 'pop3';    # Default protocol for ipop3d logs

        # Extract IP if present within brackets in the host field
        if ($raw_host_field =~ /(.*) \[([0-9.]+)\]/) {
            $host = $1;
            $ip   = $2;
        }
        elsif ($raw_host_field =~ /\[([0-9.]+)\]/) {
            $host = '';    # Hostname is empty if only IP is in brackets
            $ip   = $1;
        }
        else {
            $host = $raw_host_field;    # If no IP, the whole field is the hostname
        }
    }
    else {
        return (0);
    }
    return (1, $sec, $min, $hour, $mday, $mon, $user, $host, $ip, $prot);
}

##
# @brief Expires old POP authentication entries from the statistics hash.
#        Entries older than $expire seconds are removed.
#
sub expire_old_entries {
    my ($now)                = @_;
    my $expiration_threshold = $now - $expire;
    my $entries_deleted      = 0;
    my $map_needs_update     = 0;
    my (%stats);    # Declare local hashes for DB_File

    my @flock_fhs = open_database_stats(\%stats);
    foreach my $key (keys %stats) {
        my ($log_time, $formatted_time, $host, $ip) = split(/\^/, $stats{$key});
        next if ($log_time >= $expiration_threshold);    # Skip if not expired

        ## my $s = sprintf("Deleting expired entry: %-15s [%s] (Expired: %d sec ago)", $host, $ip, $now - $log_time);
        my $s = sprintf("del %-15s [%s] (%d sec passed)", $host, $ip, $now - $log_time);
        print_log($now, $s) if $logging;
        delete $stats{$key};
        $entries_deleted++;
    }

    if ($entries_deleted > 0) {
        sync_database_stats(\%stats);    # Sync changes to disk after deletions
        $map_needs_update = 1;           # Mark map for update if entries were removed
    }
    close_database_stats(\%stats, @flock_fhs);
    return $map_needs_update;
}

##
# @brief Creates or updates the Postfix map file and rebuilds its DBM.
#        This operation is performed atomically to prevent issues during update.
#
sub update_postfix_map {
    my (%stats);                           # Declare local hashes for DB_File
    my $temp_map_file = "$out_map.new";    # Use a temporary file for atomic update

    # Move the old map file aside if it exists, ensuring atomicity during update
    system("mv $out_map ${out_map}.old 2>/dev/null") if -f $out_map;

    my @flock_fhs = open_database_stats(\%stats);
    open(my $fh_map, '>', $temp_map_file)
      || die("Cannot create temporary map file: $temp_map_file [$!]");
    my $entry_count = 0;
    foreach my $key (sort keys %stats) {    # Sort keys for consistent map order
        $entry_count++;
        print $fh_map "$key\tOK\n";
    }
    close($fh_map);
    close_database_stats(\%stats, @flock_fhs);

    # Atomically replace the old map with the new one
    system("mv $temp_map_file $out_map") == 0
      or die "Failed to move $temp_map_file to $out_map [$!]";

    # Rebuild Postfix lookup table (cdb format)
    system("postmap cdb:${out_map}") == 0
      or die "Failed to run postmap on file: $out_map [$!]";

    ##print_log(time, "POP-before-SMTP map updated ($entry_count entries).");
    print_log(time, "popbefore map updated ($entry_count entries)");

    return;
}

##
# @brief Prints a formatted log message to the daemon's log file.
# @param $timestamp Unix timestamp of the event.
# @param $message The log message string.
#
sub print_log {
    my ($ptime, $msg) = @_;
    return unless $logging;

    my ($sec, $min, $hour, $mday, $mon, $year) = localtime($ptime);
    printf($fh_log "%04d/%02d/%02d %02d:%02d:%02d %s\n",
        $year + 1900,
        $mon + 1, $mday, $hour, $min, $sec, $msg
    );
    return;
}

# Start the main loop of the daemon
main_loop();
__END__
#
# popbefored.pl (support daemon for POP Before SMTP) by chacha.
#
#   v0.9  2001/11/26  first release.
#   v0.91 2001/11/27  change mylog format.
#   v0.92 2001/11/27  change stat db format.
#   v0.93 2001/12/01  fix bug in reguler expression.
#   v0.94 2002/09/22  add recording each user's pop last time.
#   v0.95 2002/10/15  fix bug in reguler expression. add support new mail.log format.
#   v0.96 2002/11/29  change command line string for 'ps' view.
#   v0.97 2003/01/13  add a watching newer file i-node number.
#   v0.98 2021/08/18  fix: host=UNKNOWN
#   v0.99 2022/09/03  add support dovcot, map type is changed cdb from hash, adds systemd support
#   v0.100 2024/07/26 add support a exception of microsoft imap address.
#   v0.101 2024/07/30 add support a exception of amazon pop3 host name.
#   v0.102 2024/08/19 add support a exception of microsoft imap address.
#   v0.103 2024/08/19 add support a exception of norton pop3 address.
#   v0.104 2024/09/24 add popbeforelast-exc.db for exceptions.
#   v0.105 2024/10/22 add support rfc5424 log format.
#   v0.106 2024/07/30 add support a exception of datapacket pop3 host name.
#   v0.107 2024/12/18 add support a exception of microsoft imap address.
#   v0.108 2025/06/09 refactoring and add flock().
#   v0.109 2025/06/10 refactoring.
#   v0.110 2025/06/11 added: GetFqdnWlc for local caced fqdn.
#   v0.111 2025/06/14 changed: open_databases().
#
# support on:
#   perltidy -b -l 100 --check-syntax --paren-tightness=2
#   perlcritic -3 --verbose 9
#
# vim: set ts=4 sw=4 sts=0 expandtab : ### mode line for vim
