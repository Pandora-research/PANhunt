#! /usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2014, Dionach Ltd. All rights reserved. See LICENSE file.
#
# PANhunt: search directories and sub directories for documents with PANs
# By BB

import os, sys, zipfile, re, datetime, cStringIO, argparse, time, hashlib, unicodedata, platform
import colorama
import progressbar
import filehunt
import pyodbc

app_version = '1.1'

# defaults
search_dir = u'C:\\'
output_file = u'panhunt_%s.csv' % time.strftime("%Y-%m-%d-%H%M%S")
excluded_directories_string = u'C:\\Windows,C:\\Program Files,C:\\Program Files (x86),C:\\ProgramData'
text_extensions_string =  u'.doc,.xls,.xml,.txt,.csv,.log,.tmp,.bak,.rtf,.htm,.html'
zip_extensions_string = u'.docx,.xlsx,.zip'
special_extensions_string = u'.msg,.pdf,.mdb'
mail_extensions_string = u'.pst'
other_extensions_string = u'.ost,.accdb' # checks for existence of files that can't be checked automatically

excluded_directories = None
search_extensions = {}

pan_regexs = {'Mastercard': re.compile(ur'(?:\D|^)(5[1-5][0-9]{2}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                'Visa': re.compile(ur'(?:\D|^)(4[0-9]{3}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4}(?:\ |\-|)[0-9]{4})(?:\D|$)'), \
                'AMEX': re.compile(ur'(?:\D|^)((?:34|37)[0-9]{2}(?:\ |\-|)[0-9]{6}(?:\ |\-|)[0-9]{5})(?:\D|$)')}

###################################################################################################################################
#   ____ _                         
#  / ___| | __ _ ___ ___  ___  ___ 
# | |   | |/ _` / __/ __|/ _ \/ __|
# | |___| | (_| \__ \__ \  __/\__ \
#  \____|_|\__,_|___/___/\___||___/
#                                  
###################################################################################################################################


class PANFile(filehunt.AFile):
    """ PANFile: class for a file that can check itself for PANs"""

    def __init__(self, filename, file_dir):
        
        filehunt.AFile.__init__(self, filename, file_dir)
        #self.type = None # DOC, ZIP, MAIL, SPECIAL, OTHER  


    def check_text_regexs(self, text, regexs, sub_path):
        """Uses regular expressions to check for PANs in text"""

        for brand, regex in regexs.items():
            try:
                text.decode('ascii')
            except:
                text = re.sub(r"\x00+", "", text, flags=re.UNICODE)
            pans = regex.findall(text)
            if pans:
                for pan in pans:
                    if PAN.is_valid_luhn_checksum(pan):
                        self.matches.append(PAN(self.path, sub_path, brand, pan))

    def check_pdf_regexs(self, text, regexs, sub_path):
        """Uses regular expressions to check for PANs in PDF files"""

        for brand, regex in regexs.items():
            pdftext = text.tree.xpath("//*[re:test(text(), '"+str(regex.pattern)+"')]", namespaces={"re": "http://exslt.org/regular-expressions"})
            for match in pdftext:
                self.check_text_regexs(match.text, regexs, '')

    def check_access_regexs(self, dbfile, dbtype, regexs):
        """Uses regular expressions to check for PANs in Access MDB files"""

        # Try to connect to the database
        try:
            conn = pyodbc.connect('DRIVER={Microsoft Access Driver (*.mdb)};DBQ='+dbfile)
            cursor = conn.cursor()

            # Loop through each table
            for table_name in cursor.tables(tableType='TABLE'):
                SQL = 'SELECT * FROM '+str(table_name[2])+';'
                tableCursor = conn.cursor()
                rowcount = 0

                # Loop through each row in the table
                for row in tableCursor.execute(SQL):
                    rowdata = ''
                    rowlen = len(row)
                    tblcount = 0

                    # Concatenate table contents
                    while(tblcount < rowlen):
                        if (tblcount+1) == rowlen:
                            rowdata += str(row[tblcount])
                        else:
                            rowdata += str(row[tblcount]) + ','

                        tblcount += 1
    
                    self.check_text_regexs(rowdata, regexs, str('Table: '+table_name[2])+' => Row: '+str(rowcount+1))
                    rowcount += 1
        except:
            pass


class PAN:
    """PAN: A class for recording PANs, their brand and where they were found"""

    def __init__(self, path, sub_path, brand, pan):
        
        self.path, self.sub_path, self.brand, self.pan = path, sub_path, brand, pan


    def __repr__(self, mask_pan=True):

        if mask_pan:
            pan_out = self.get_masked_pan()
        else:
            pan_out = self.pan
        return '%s %s:%s' % (self.sub_path, self.brand, pan_out)


    def get_masked_pan(self):
        return self.pan[0:7] + re.sub('\d','*',self.pan[7:-4]) + self.pan[-4:]


    @staticmethod
    def is_valid_luhn_checksum(pan):
        """ from wikipedia: http://en.wikipedia.org/wiki/Luhn_algorithm"""

        pan = re.sub('[^\d]','', pan)

        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(pan)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = 0
        checksum += sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        
        return checksum % 10 == 0



###################################################################################################################################
#  __  __           _       _        _____                 _   _                 
# |  \/  | ___   __| |_   _| | ___  |  ___|   _ _ __   ___| |_(_) ___  _ __  ___ 
# | |\/| |/ _ \ / _` | | | | |/ _ \ | |_ | | | | '_ \ / __| __| |/ _ \| '_ \/ __|
# | |  | | (_) | (_| | |_| | |  __/ |  _|| |_| | | | | (__| |_| | (_) | | | \__ \
# |_|  |_|\___/ \__,_|\__,_|_|\___| |_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
#
###################################################################################################################################       


def get_text_hash(text):

    if type(text) is unicode:
        encoded_text = text.encode('utf-8')
    else:
        encoded_text = text
    return hashlib.sha512(encoded_text+'PAN').hexdigest()


def add_hash_to_file(text_file):

    text = filehunt.read_unicode_file(text_file)
    hash_check = get_text_hash(text)

    text += os.linesep + get_text_hash(text)
    filehunt.write_unicode_file(text_file, text)


def check_file_hash(text_file):
    
    text_output = filehunt.read_unicode_file(text_file)
    hash_pos = text_output.rfind(os.linesep)
    hash_in_file =  text_output[hash_pos+len(os.linesep):]
    hash_check = get_text_hash(text_output[:hash_pos])
    if hash_in_file == hash_check:
        print colorama.Fore.GREEN + 'Hashes OK'
    else:
        print colorama.Fore.RED + 'Hashes Not OK'
    print colorama.Fore.WHITE + hash_in_file +'\n' + hash_check


def output_report(search_dir, excluded_directories_string, all_files, total_files_searched, pans_found, output_file, mask_pans):

    pan_sep = u'\n\t'
    pan_report = u'Path,File,File Size,File Modified Date,Details,Type,PAN\n'

    for afile in sorted([afile for afile in all_files if afile.matches]):
        total_matches = len(afile.matches)
        match_count = 0

        while(match_count < total_matches):
            pan_report += u'%s,%s,%s,%s,%s,%s,%s' % (afile.path.rsplit('\\', 1)[0], afile.path.rsplit('\\', 1)[1], afile.size_friendly(), afile.modified.strftime('%m/%d/%Y'), str(afile.matches[match_count]).rsplit('Visa', 1)[0].rsplit('Master', 1)[0].rsplit('AMEX', 1)[0], str(afile.matches[match_count]).rsplit(':', 1)[0].rsplit(' ', 1)[1], str(afile.matches[match_count]).rsplit(':', 1)[1])
            pan_report += '\n'
            match_count += 1

        pan_header = u'FOUND PANs: %s (%s %s)' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))
        print colorama.Fore.RED + filehunt.unicode2ascii(pan_header)
        pan_list = u'\t' + pan_sep.join([pan.__repr__(mask_pans) for pan in afile.matches])
        print colorama.Fore.YELLOW + filehunt.unicode2ascii(pan_list)
    
    if len([afile for afile in all_files if afile.type == 'OTHER']) <> 0:
        pan_report += u'Interesting Files to check separately:\n'
    for afile in sorted([afile for afile in all_files if afile.type == 'OTHER']):
        pan_report += u'%s (%s %s)\n' % (afile.path, afile.size_friendly(), afile.modified.strftime('%d/%m/%Y'))

    pan_report += u'\n\t'
    pan_report += u'PAN Hunt Report - %s\n%s\n' % (time.strftime("%H:%M:%S %d/%m/%Y"), '='*100)
    pan_report += u'Searched %s\nExcluded %s\n' % (search_dir, excluded_directories_string)
    pan_report += u'Command: %s\n' % (' '.join(sys.argv))
    pan_report += u'Uname: %s\n' % (' | '.join(platform.uname()))
    pan_report += u'Searched %s files. Found %s possible PANs.\n%s\n\n' % (total_files_searched, pans_found, '='*100)
    pan_report += u'\n\t'

    pan_report = pan_report.replace('\n', os.linesep)

    print colorama.Fore.WHITE + 'Report written to %s' % filehunt.unicode2ascii(output_file)
    filehunt.write_unicode_file(output_file, pan_report)
    add_hash_to_file(output_file)


def set_global_parameters():

    global excluded_directories_string, text_extensions_string, zip_extensions_string, special_extensions_string, mail_extensions_string, other_extensions_string, excluded_directories, search_extensions

    excluded_directories = [exc_dir.lower() for exc_dir in excluded_directories_string.split(',')]    
    search_extensions['TEXT'] = text_extensions_string.split(',')
    search_extensions['ZIP'] = zip_extensions_string.split(',')
    search_extensions['SPECIAL'] = special_extensions_string.split(',')
    search_extensions['MAIL'] = mail_extensions_string.split(',')
    search_extensions['OTHER'] = other_extensions_string.split(',')


def hunt_pans(gauge_update_function=None):

    global search_dir, excluded_directories, search_extensions

    # find all files to check
    all_files = filehunt.find_all_files_in_directory(PANFile, search_dir, excluded_directories, search_extensions, gauge_update_function)

    # check each file
    total_docs, doc_pans_found = filehunt.find_all_regexs_in_files([afile for afile in all_files if not afile.errors and afile.type in ('TEXT','ZIP','SPECIAL')], pan_regexs, search_extensions, 'PAN', gauge_update_function)
    # check each pst message and attachment
    total_psts, pst_pans_found = filehunt.find_all_regexs_in_psts([afile for afile in all_files if not afile.errors and afile.type == 'MAIL'], pan_regexs, search_extensions, 'PAN', gauge_update_function)

    total_files_searched = total_docs + total_psts
    pans_found = doc_pans_found + pst_pans_found

    return total_files_searched, pans_found, all_files


###################################################################################################################################
#  __  __       _       
# |  \/  | __ _(_)_ __  
# | |\/| |/ _` | | '_ \ 
# | |  | | (_| | | | | |
# |_|  |_|\__,_|_|_| |_|
#
###################################################################################################################################


if __name__ == "__main__":

    colorama.init()
  
    # Command Line Arguments
    arg_parser = argparse.ArgumentParser(prog='panhunt', description='PAN Hunt v%s: search directories and sub directories for documents containing PANs.' % (app_version), formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-s', dest='search', default=search_dir, help='base directory to search in')
    arg_parser.add_argument('-x', dest='exclude', default=excluded_directories_string, help='directories to exclude from the search')
    arg_parser.add_argument('-t', dest='textfiles', default=text_extensions_string, help='text file extensions to search')
    arg_parser.add_argument('-z', dest='zipfiles', default=zip_extensions_string, help='zip file extensions to search')
    arg_parser.add_argument('-e', dest='specialfiles', default=special_extensions_string, help='special file extensions to search')
    arg_parser.add_argument('-m', dest='mailfiles', default=mail_extensions_string, help='email file extensions to search')
    arg_parser.add_argument('-l', dest='otherfiles', default=other_extensions_string, help='other file extensions to list')
    arg_parser.add_argument('-o', dest='outfile', default=output_file, help='output file name for PAN report')
    arg_parser.add_argument('-u', dest='unmask', action='store_true', default=False, help='unmask PANs in output')
    arg_parser.add_argument('-c', dest='checkfilehash', help=argparse.SUPPRESS) # hidden argument

    args = arg_parser.parse_args()    
    
    if args.checkfilehash:
        check_file_hash(args.checkfilehash)
        sys.exit()
    
    search_dir = unicode(args.search)
    output_file = unicode(args.outfile)
    excluded_directories_string = unicode(args.exclude)
    text_extensions_string = unicode(args.textfiles)    
    zip_extensions_string = unicode(args.zipfiles)
    special_extensions_string = unicode(args.specialfiles)
    mail_extensions_string = unicode(args.mailfiles)
    other_extensions_string = unicode(args.otherfiles)
    mask_pans = not args.unmask
    
    set_global_parameters()

    total_files_searched, pans_found, all_files = hunt_pans()

    # report findings
    output_report(search_dir, excluded_directories_string, all_files, total_files_searched, pans_found, output_file, mask_pans)