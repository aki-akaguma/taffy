#!/usr/bin/perl
#
# popbefore.pl
#   print status of popbefore
#
use 5.028;    # Explicitly use Perl 5.28 (enables strict and warnings by default)
use warnings;

#---- Modules ----
use Getopt::Std;
use DB_File;
use Fcntl qw(:flock O_RDONLY O_RDWR);

#---- Configuration ----
my $VERSION        = '0.98';
my $STATS_FILE     = '/var/local/popbefore.db';          # popbefore database file path
my $PLAST_FILE     = '/var/local/popbeforelast.db';      # pop last database file path
my $PLAST_EXC_FILE = '/var/local/popbeforelast-exc.db';  # pop last database of exceptions file path
my $DB_FILE_PERMS  = 0o666;                              # Default permissions for new DB files

#---- Main Execution ----
# Command-line options parsing
## no critic (Variables::ProhibitPackageVars)
our ($opt_h, $opt_s, $opt_u, $opt_d, $opt_e);

MAIN: {
    # Check the return value of getopts for invalid options
    unless (getopts('hsud:e')) {
        say STDERR "Invalid option. Use -h for help.";
        exit 1;
    }

    # Handle options
    ## no critic (ControlStructures::ProhibitCascadingIfElse)
    if ($opt_h) {
        print_help();
        exit 0;    # Exit successfully after printing help
    }
    elsif ($opt_d) {
        delete_last_entry($opt_d);
    }
    elsif ($opt_u) {
        show_last_pop_times();
    }
    elsif ($opt_s) {
        show_popbefore_status();
    }
    else {
        # Default action if no specific option is provided
        show_popbefore_status();
    }

    exit 0;    # Script finishes successfully
}

#--- Subroutines ---

# @brief    Prints the usage instructions and options to STDERR.
sub print_help {
    say STDERR "[Usage] $0 [-h] [{-s|-u|-d user}]";
    say STDERR "  -h        Print this help message";
    say STDERR "  -s        Show status of popbefore";
    say STDERR "  -u        Show each user's last pop time";
    say STDERR "  -d user   Delete user's last pop time entry";
    say STDERR "  -e        Operate on the exceptions database (popbeforelast-exc.db)";

    return;
}

# @brief  Opens a DB_File database with the specified mode and applies a file flock.
# @param  $db_file (string): Path to the database file.
# @param  $mode (integer): File access mode (e.g., O_RDONLY for read, O_RDWR for read/write).
# @returns
#   A list containing the tied hash reference and the flock filehandle on success.
#   Dies if the flock file cannot be opened or flocked, or if the database cannot be tied.
sub open_db {
    my ($db_file, $mode) = @_;

    my $flock_path = "$db_file.flock";
    my $flock_fh;
    my $db_tied_hash_ref = {};    # Anonymous hash reference to tie DB_File to

    ## no critic (InputOutput::RequireBriefOpen)
    # Open flock file. Using '>>' ensures creation if it doesn't exist.
    open($flock_fh, '>>', $flock_path)
      or die("Cannot open flock file: $flock_path [$!]\n");

    # Acquire flock: LOCK_EX for write mode, LOCK_SH for read-only mode
    my $flock_type = ($mode == O_RDWR) ? LOCK_EX : LOCK_SH;
    flock($flock_fh, $flock_type)
      or die("Cannot get flock on file: $flock_path [$!]\n");

    # Tie DB_File to the anonymous hash reference
    tie(%$db_tied_hash_ref, "DB_File", $db_file, $mode, $DB_FILE_PERMS, $DB_HASH)
      or die("Cannot open database file: $db_file [$!]\n");

    # Return the hash reference and the flock filehandle
    return ($db_tied_hash_ref, $flock_fh);
}

# @brief  Unties the DB_File database and releases the file flock.
# @param  $db_tied_hash_ref (hash reference): The hash reference that DB_File was tied to.
# @param  $flock_fh (filehandle): The filehandle for the flock file.
sub close_db {
    my ($db_tied_hash_ref, $flock_fh) = @_;

    # Untie the hash to flush changes and close the DB. Warn on failure.
    untie(%$db_tied_hash_ref)
      or warn "Failed to untie database: $!\n";

    # Close the flock filehandle. Warn on failure.
    close($flock_fh)
      or warn "Failed to close flock file: $!\n";

    return;
}

# @brief  Displays overall popbefore statistics from the main stats database.
sub show_popbefore_status {

    # Open the database in read-only mode
    my ($db_hash_ref, $flock_fh) = open_db($STATS_FILE, O_RDONLY);

    ##say "--- Popbefore Status ---";
    if (keys %$db_hash_ref) {
        ## Sort and print each key-value pair
        foreach my $key (sort keys %$db_hash_ref) {
            say "$key\t$$db_hash_ref{$key}";
        }
    }
    else {
        say "No data available.";
    }

    # Close the database and release flock
    close_db($db_hash_ref, $flock_fh);

    return;
}

# @brief  Displays last pop times for users from either the main or exception database.
sub show_last_pop_times {

    # Determine which file to open based on the -e option
    my $file_to_open = ($opt_e) ? $PLAST_EXC_FILE : $PLAST_FILE;

    # Open the database in read-only mode
    my ($db_hash_ref, $flock_fh) = open_db($file_to_open, O_RDONLY);

    ##say "--- Last Pop Times ---";
    if (keys %$db_hash_ref) {
        ## Sort and print each user's last pop time
        foreach my $user (sort keys %$db_hash_ref) {
            say "$user\t$$db_hash_ref{$user}";
        }
    }
    else {
        say "No data available.";
    }

    # Close the database and release flock
    close_db($db_hash_ref, $flock_fh);

    return;
}

# @brief  Deletes a user's last pop time entry from the database.
# @param  $user (string): The username whose entry should be deleted.
sub delete_last_entry {
    my ($user) = @_;

    # Determine which file to open based on the -e option
    my $file_to_open = ($opt_e) ? $PLAST_EXC_FILE : $PLAST_FILE;

    # Open the database in read/write mode
    my ($db_hash_ref, $flock_fh) = open_db($file_to_open, O_RDWR);

    # Check if the user exists before attempting to delete
    if (exists $$db_hash_ref{$user}) {
        delete $$db_hash_ref{$user};
        say "Entry for user '$user' deleted successfully.";
    }
    else {
        say "User '$user' not found.";
    }

    # Close the database and release flock
    close_db($db_hash_ref, $flock_fh);

    return;
}

__END__
#
# popbefore.pl
#    print status of popbefore
#
#   v0.92 2001/11/27  change stat db format.
#   v0.94 2002/09/22  add showing each user's pop last time.
#   v0.95 2002/11/14  add deleting user's last time from popbeforelast.db.
#   v0.96 2024/09/24  add popbeforelast-exc.db support.
#   v0.97 2025/06/10  refactoring and add flock().
#   v0.98 2025/06/10  refactoring.
#
# support on:
#   perltidy -b -l 100 --check-syntax --paren-tightness=2
#   perlcritic -3 --verbose 9
#
# vim: set ts=4 sw=4 sts=0 expandtab : ### mode line for vim
