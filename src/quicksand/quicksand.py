#!/usr/bin/env python
###
### QuickSand 2: Python3 Version Copyright (c) 2025 @tylabs
### https://github.com/tylabs/quicksand
###
### Python3 module and executable to process suspected document or PDF malware for exploit detection
### The recommended use of this module is to detect suspicious documents or PDFs by type of exploit, then
### based on the vulnerable version of Office or PDF Reader, use a dynamic sandbox to extract IOCs.
###
### QuickSand uses Yara-Python (exploit detection), pdfreader (Handle PDF Object decoding), 
### olefile (parse OLE objects), and oletools (parse RTF).
###
### quicksand v2 is a complete rewrite from c to Python. Removes XOR exe detection
### as this is less useful as most modern document exploits use varied encoding
### through VBA macros. Adds PDF combining the detection of Cryptam and PDFExaminer
### into one tool.
###

import sys
import re
import olefile
import binascii
import yara
from io import BytesIO
import zipfile
import zlib
import os
import base64
import pdfreader
from pdfreader import PDFDocument
from oletools import rtfobj
from oletools import olevba
from oletools import crypto
from os import listdir
from os.path import isfile, join
import hashlib
import time
import string
import traceback
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, BinaryIO


class quicksand:
    __version__ = '2.1.0'
    __author__ = "tylabs.com"
    __copyright__ = "Copyright 2025, @tylabs"
    __license__ = "MIT"
    
    try:
        # Use pathlib for file paths
        base_dir = Path(__file__).parent
        exploityara = str(base_dir / 'quicksand_exploits.yara')
        execyara = str(base_dir / 'quicksand_exe.yara')
        pdfyara = str(base_dir / 'quicksand_pdf.yara')
    except:
        exploityara = 'quicksand_exploits.yara'
        execyara = 'quicksand_exe.yara'
        pdfyara = 'quicksand_pdf.yara'
    
    def msg(self, message: Any) -> None:
        """Log a debug message if debug mode is enabled.
        
        Args:
            message: The message to log
        """
        if self.debug:
            print(f"{time.time()}: {message}")

    def readFile(self, filename):
        """Read a file and return its contents as bytes.
        
        Args:
            filename: The path to the file to read.
            
        Returns:
            bytes: The contents of the file, or empty bytes if the file is not found.
        """
        try:
            with open(filename, "rb") as f:
                return f.read()
        except:
            self.msg("ERROR: file not found")
            return b''
    
    @staticmethod
    def readDir(directory: str, capture: bool = False, strings: bool = True, 
               debug: bool = False, timeout: int = 0, exploityara: Optional[str] = None, 
               execyara: Optional[str] = None, pdfyara: Optional[str] = None, 
               password: Optional[str] = None) -> Dict[str, Dict]:
        """Process all files in a directory.
        
        Args:
            directory: Path to the directory containing files to analyze
            capture: Whether to capture stream content
            strings: Whether to capture YARA match strings
            debug: Whether to enable debug logging
            timeout: Timeout in seconds (0 for no timeout)
            exploityara: Path to exploit YARA rules
            execyara: Path to executable YARA rules
            pdfyara: Path to PDF YARA rules
            password: Password for encrypted documents
            
        Returns:
            Dict mapping filenames to analysis results
        """
        out = {}
        try:
            dir_path = Path(directory)
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    q = quicksand(str(file_path), capture=capture, strings=strings, 
                                 debug=debug, timeout=timeout, exploityara=exploityara, 
                                 execyara=execyara, pdfyara=pdfyara, password=password)
                    q.process()
                    out[str(file_path)] = q.results
        except Exception as e:
            print(f"Error processing directory {directory}: {e}")
        return out


    def mapStructure(self, parent, loc):
        None

    def __init__(self, data: Union[str, bytes], capture: bool = False, strings: bool = True, 
              debug: bool = False, timeout: int = 0, exploityara: Optional[str] = None, 
              execyara: Optional[str] = None, pdfyara: Optional[str] = None, 
              password: Optional[str] = None):
        """Initialize a quicksand analyzer.
        
        Args:
            data: Either a file path or raw bytes data to analyze
            capture: Whether to capture stream content
            strings: Whether to capture YARA match strings
            debug: Whether to enable debug logging
            timeout: Timeout in seconds (0 for no timeout)
            exploityara: Path to exploit YARA rules (overrides default)
            execyara: Path to executable YARA rules (overrides default)
            pdfyara: Path to PDF YARA rules (overrides default)
            password: Password for encrypted documents
        """
        self.results = {'results': {}}
        self.structure = ""
        self.capture = capture
        self.strings = strings
        self.debug = debug
        self.password = password
        self.results['score'] = 0
        self.results['warning'] = 0
        self.results['exploit'] = 0
        self.results['execute'] = 0
        self.results['feature'] = 0
        self.results['packages'] = []
        self.timeout = timeout
        
        if self.capture:
            self.results['streams'] = {}
        
        # Handle data as file path or raw bytes
        if isinstance(data, str) and Path(data).is_file():
            self.results['filename'] = data
            self.data = self.readFile(data)
        else:
            self.results['filename'] = None
            self.data = data
            
        # Override default YARA rule paths if provided
        if exploityara is not None:
            self.exploityara = exploityara
        if execyara is not None:
            self.execyara = execyara
        if pdfyara is not None:
            self.pdfyara = pdfyara
            
        # Compile YARA rules
        self.exploitrules = yara.compile(filepath=self.exploityara)
        self.execrules = yara.compile(filepath=self.execyara)
        self.pdfrules = yara.compile(filepath=self.pdfyara)
           

    def format_yara_strings(self, match_strings: List) -> str:
        """Convert Yara match strings to a readable string format.
        
        Args:
            match_strings: List of YARA match strings objects
            
        Returns:
            Formatted string representation of the matches
        """
        if not match_strings:
            return ""
        
        result = []
        
        # YARA 4.3.0+ API
        for match in match_strings:
            # Check if this is a StringMatch object (YARA 4.3.0+)
            if hasattr(match, 'identifier') and hasattr(match, 'instances'):
                identifier = match.identifier
                # Loop through all instances of this match
                for instance in match.instances:
                    if hasattr(instance, 'matched_data') and hasattr(instance, 'offset'):
                        offset = instance.offset
                        data = instance.matched_data
                        
                        # Try to decode the data
                        try:
                            string_data = data.decode('utf-8', errors='replace')
                        except (UnicodeDecodeError, AttributeError):
                            string_data = data.hex() if data else "[empty]"
                        
                        result.append(f"{identifier} at offset {offset}: {string_data}")
            
            # Fallback for older YARA versions or direct tuple access
            elif isinstance(match, tuple) and len(match) >= 3:
                identifier, offset, data = match
                try:
                    string_data = data.decode('utf-8', errors='replace')
                except (UnicodeDecodeError, AttributeError):
                    string_data = data.hex() if data else "[empty]"
                result.append(f"{identifier} at offset {offset}: {string_data}")
            
            # Last resort fallback
            else:
                try:
                    result.append(f"Match data: {str(match)}")
                except Exception:
                    result.append("Unprocessable match data")
        
        return "\n".join(result)

    @staticmethod
    def carve(item: bytes, separator: bytes) -> List[bytes]:
        """Split binary data on a separator and return the items.
        
        Args:
            item: Binary data to split
            separator: Separator to split on
            
        Returns:
            List of binary chunks
        """
        return [separator + e for e in item.split(separator) if e]


    def scan_exploit(self, item: bytes, loc: str) -> None:
        """Scan data for exploits using YARA rules.
        
        Args:
            item: Binary data to scan
            loc: Location identifier for reporting
        """
        matches = self.exploitrules.match(data=item)

        if not matches:
            return

        for match in matches:
            rule_type = "exploit"
            desc = ""
            mitre = ""
            rank = None
            is_exe = False
            is_feature = False
            is_warning = False
            is_exploit = False
            
            # Extract metadata from the match
            try:
                desc = match.meta.get('desc', "")
                mitre = match.meta.get('mitre', "")
                rank = match.meta.get('rank')
                
                is_exe = match.meta.get('is_exe', False)
                if is_exe:
                    self.results['execute'] += 1
                    
                is_exploit = match.meta.get('is_exploit', False)
                if is_exploit:
                    self.results['exploit'] += 1
                    
                is_warning = match.meta.get('is_warning', False)
                if is_warning:
                    self.results['warning'] += 1
                    
                is_feature = match.meta.get('is_feature', False)
                if is_feature:
                    self.results['feature'] += 1
            except (AttributeError, KeyError) as e:
                self.msg(f"Error extracting metadata: {e}")
                
            # Update score if rank is available
            if rank is not None:
                self.results['score'] += int(rank)
            
            # Format matched strings if enabled
            if self.strings:
                if isinstance(match.strings, list):
                    formatted_strings = self.format_yara_strings(match.strings)
                else:
                    formatted_strings = str(match.strings)
                result_entry = {'rule': match.rule, 'desc': desc, 'strings': formatted_strings, 'type': rule_type, 'mitre': mitre}
            else:
                result_entry = {'rule': match.rule, 'desc': desc, 'type': rule_type, 'mitre': mitre}
            
            # Add the result to the appropriate location
            if loc in self.results['results']:
                self.results['results'][loc].append(result_entry)
            else:
                self.results['results'][loc] = [result_entry]
                
            self.msg(f"YARA EXPLOIT: {loc}:{match.rule}")



    def scan_exec(self, item, loc):
        matches = self.execrules.match(data=item)

        if matches:
            for m in matches:
                rtype = "execute"
                desc = ""
                mitre = ""
                rank = None
                is_exe = False
                is_feature = False
                is_warning = False
                is_exploit = False
                
                try:
                    desc = m.meta['desc']
                except:
                    None
                try:
                    mitre = m.meta['mitre']
                except:
                    None
                try:
                    rank = m.meta['rank']
                except:
                    None
                try:
                    is_exe = m.meta['is_exe']
                    if is_exe == True:
                         self.results['execute'] += 1
                except:
                    None
                try:
                    is_exploit = m.meta['is_exploit']
                    if is_exploit == True:
                         self.results['exploit'] += 1
                except:
                    None
                try:
                    is_warning = m.meta['is_warning']
                    if is_warning == True:
                         self.results['warning'] += 1
                except:
                    None
                try:
                    is_feature = m.meta['is_feature']
                    if is_feature == True:
                         self.results['feature'] += 1
                except:
                    None

                    
                if rank != None:
                    self.results['score'] += int(rank)
                       
                if loc in self.results['results']:
                    if self.strings:
                        if isinstance(m.strings, list):
                            formatted_strings = self.format_yara_strings(m.strings)
                        else:
                            formatted_strings = str(m.strings)
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'strings': formatted_strings, 'type': rtype, 'mitre': mitre})
                    else:
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre})
                else:
                    if self.strings:
                        if isinstance(m.strings, list):
                            formatted_strings = self.format_yara_strings(m.strings)
                        else:
                            formatted_strings = str(m.strings)
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'strings': formatted_strings, 'type': rtype, 'mitre': mitre}]
                    else:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre}]
                #quicksand.msg(self, "YARA EXEC: "+ str(loc)+ ":" + str(m.rule))
                #quicksand.msg(self, m.strings)


    def scan_pdf(self, item, loc):
        matches = self.pdfrules.match(data=item)

        if matches:
            for m in matches:
                rtype = "pdf"
                desc = ""
                mitre = ""
                rank = None
                is_exe = False
                is_feature = False
                is_warning = False
                is_exploit = False
                
                try:
                    desc = m.meta['desc']
                except:
                    None
                try:
                    mitre = m.meta['mitre']
                except:
                    None
                try:
                    rank = m.meta['rank']
                except:
                    None
                try:
                    is_exe = m.meta['is_exe']
                    if is_exe == True:
                         self.results['execute'] += 1
                except:
                    None
                try:
                    is_exploit = m.meta['is_exploit']
                    if is_exploit == True:
                         self.results['exploit'] += 1
                except:
                    None
                try:
                    is_warning = m.meta['is_warning']
                    if is_warning == True:
                         self.results['warning'] += 1
                except:
                    None
                try:
                    is_feature = m.meta['is_feature']
                    if is_feature == True:
                         self.results['feature'] += 1
                except:
                    None

                    
                if rank != None:
                    self.results['score'] += int(rank)
                        
                if loc in self.results['results']:
                    if self.strings:
                        if isinstance(m.strings, list):
                            formatted_strings = self.format_yara_strings(m.strings)
                        else:
                            formatted_strings = str(m.strings)
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'strings': formatted_strings, 'type': rtype, 'mitre': mitre})
                    else:
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre})
                else:
                    if self.strings:
                        if isinstance(m.strings, list):
                            formatted_strings = self.format_yara_strings(m.strings)
                        else:
                            formatted_strings = str(m.strings)
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'strings': formatted_strings, 'type': rtype, 'mitre': mitre}]
                    else:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre}]
 
                #quicksand.msg(self, m.strings)


    def analyse_pdf(self, doc, loc):
        try:
            quicksand.scan_pdf(self, doc, str(loc))
            #consider removing the obfuscated content here rather than in yara
            try:
                if self.password != None:
                    pdf = PDFDocument(doc, password=self.password)
                else:
                    pdf = PDFDocument(doc)
            except:
                pdf = PDFDocument(doc)

            #quicksand.msg(self, pdf.header.version)
            #quicksand.msg(self, pdf.pages())
            #quicksand.msg(self, pdf.catalog())
            #quicksand.msg(self, pdf.parser)
            for block in re.findall(rb'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))',doc):
                if len(block[2]) != 0:
                    try:
                        num = int(block[2])
                        gen = int(block[3])
                        self.msg(f"obj {num} {gen}")
                        self.structure += f"{num}-{gen},"
                    except ValueError:
                        self.msg(f"Error parsing numeric token in PDF object: {block[2]}")
                        continue
                else:
                    self.structure += block[5].decode("utf-8") + ","
                    self.msg(f"obj {block[5].decode('utf-8')}")

            # validate that there's no hidden pdf objects by parsing them out
            for block in re.findall(rb'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj(\x0a|\x0d|\x20)<<[^>]{1,200}\x2fFilter)',doc):
                self.msg(block)
                if self.timeout > 0 and time.time() - self.results['started'] > self.timeout:
                    self.results['skip'] = 1
                    continue

                #for block in re.findall(b'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))',doc):
                #quicksand.msg (self,str(time.time()) + " " + str(block))
                if block[2]:
                    try:
                        num = int(block[2])
                        gen = int(block[3])
                        self.msg(f"stream {num} {gen}")
                        
                        try:
                            raw_obj = pdf.locate_object(num, gen)
                            obj = pdf.build(raw_obj)
                        except (ValueError, pdfreader.exceptions.PDFSyntaxError) as e:
                            self.msg(f"Error parsing PDF object {num} {gen}: {e}")
                            continue
                        except Exception as e:
                            self.msg(e)
                            continue
                            
                        try:
                            if type(obj) == pdfreader.types.objects.StreamBasedObject:
                                #quicksand.msg(self, "scan stream " + str (obj.get('Filter')) + " " + str(len(obj.filtered)))
                                #quicksand.scan_pdf(self, obj.data,str(loc) + "-pdf_" + str(num) + "_" + str(gen))
                                pdf_object_loc = f"{loc}-pdf_{num}_{gen}"
                                quicksand.scan_pdf(self, obj.filtered, pdf_object_loc)
                                if self.capture:
                                    self.results['streams'][pdf_object_loc] = obj.filtered
                            #else:
                                #quicksand.msg(self, obj)
                        except Exception as e:
                            self.msg(e)
                    except ValueError as e:
                        self.msg(f"Error parsing numeric token in PDF stream: {block[2]}, {block[3]}")
                        continue
                else:
                    #quicksand.msg (self,"special " + str(block[5].decode()) )
                    None
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            line_number = exc_traceback.tb_lineno
            self.msg(f"Error parsing PDF on line {line_number} due to {e}")
            

            if loc in self.results['results']:
                self.results['results'][loc].append({'rule': "pdf_malformed", 'desc': f"WARNING: PDF is malformed. Error parsing PDF on line {line_number} due to {e}", 'strings': '', 'type': 'structure'})
            else:
                self.results['results'][loc] = [{'rule': "pdf_malformed", 'desc': f"WARNING: PDF is malformed. Error parsing PDF on line {line_number} due to {e}", 'strings': '', 'type': 'structure'}]
           


    def analyse_openxml(self, doc,loc):
        try:
            filebytes = BytesIO(doc)
            myzipfile = zipfile.ZipFile(filebytes,allowZip64=True)
            for name in myzipfile.namelist():
                #quicksand.msg(self, str(loc) + "/" + str(name))
                foofile = myzipfile.open(name)
                subdata = foofile.read()
                if len(subdata) > 10:
                    #quicksand.msg (self,"yara scan")
                    quicksand.analyse(self, subdata, str(loc) + "-" + str(name))
                    if self.capture:
                        self.results['streams'][str(loc) + "-" + str(name)] = subdata

        except Exception as e:
            return e
        return "ok"
    
    
    def rtf_block(self, block, loc):
        # decode a hex block into bytes
        try:
            obj = bytes.fromhex(re.sub(rb'[ \x0a\x0d]', b'', block).decode('utf8'))
        except:
            obj = block

        self.msg(f"RTF obj size {len(obj)}")
        if self.capture:
            self.results['streams'][loc] = obj
        
        #scan objects
        quicksand.scan_exploit(self, obj, str(loc))
        quicksand.scan_exec(self, obj, str(loc))
        #extract OLE files
        if re.search(binascii.unhexlify(b'd0cf11e0'), obj, re.IGNORECASE):
            self.msg(f"{loc} has embedded ole doc")
            elements = quicksand.carve(obj, binascii.unhexlify(b'd0cf11e0'))
            elements.pop(0)
            self.msg(f"There may be this many ole: {len(elements)}")

            directory = 0
            for i in range(0, len(elements)):
                #quicksand.msg(self, elements[i])
                newloc = f"ole{i}"
                self.structure += f"{newloc},"

                r = quicksand.analyse_ole(self, elements[i], f"{loc}-{newloc}")
                if self.capture:
                    self.results['streams'][f"{loc}{newloc}"] = elements[i]

                if "negative" in str(r) and len(elements) > 1:
                    self.msg(f"range {directory} {i}")
                    r = quicksand.analyse_ole(self, b''.join(elements[directory : i+1]), f"{loc}-oleg{directory}-{i}")

                    directory = i+1
                    if self.capture:
                        self.results['streams'][f"{loc}-oler{directory}-{i}"] = b''.join(elements[directory : i+1])
                    else:
                        if self.capture:
                            self.results['streams'][f"{loc}-olea-{i}"] =  elements[i]

        #extract openxml zip
        if re.search(binascii.unhexlify(b'504B030414000600'), obj, re.IGNORECASE):
            self.msg("has embedded openxml doc")
            elements = quicksand.carve(obj, binascii.unhexlify(b'504B030414000600'))
            elements.pop(0)
            #quicksand.msg (self,"there may this many openxml " + str(len(elements)))

            directory = 0
            for i in range(0, len(elements)):
                self.msg(element)
                self.msg(" -element 1 ")
                newloc = f"openxml{i}"
                self.structure += f"{newloc},"
                r = quicksand.analyse_openxml(self, elements[i], f"{loc}-{newloc}")
                if self.capture:
                    self.results['streams'][f"{loc}{newloc}"] = elements[i]

                if "negative" in str(r) and len(elements) > 1:
                    self.msg(f"range {directory} {i}")
                    r = quicksand.analyse_openxml(self, b''.join(elements[directory : i+1]), f"{loc}-openxmlg{directory}-{i}")
                    directory = i+1
                    if self.capture:
                        self.results['streams'][f"{loc}-openxmlr{directory}-{i}"] = b''.join(elements[directory : i+1])
                else:
                    if self.capture:
                        self.results['streams'][f"{loc}-openxmla{i}"] = elements[i]


    def analyse_rtf(self, doc, loc):
        #quicksand.msg (self,"Rtf")

        quicksand.msg(self, doc[:100])
        #scan objects
        quicksand.scan_exploit(self, doc, str(loc))

        doc = re.sub(rb'\d}(\d{1})', b'}<1>',doc)
	# fix for oletools rtf parse c88d0f7d623b2a2c066dd6b15597d1f4c44d89e7a8e660e28c3494f441826ea5
        doc = re.sub(rb'{ods(\d{1})', b'{ods <1>',doc)
        #doc = re.sub(rb'\\objdata \{\\ods', b'',doc)
        quicksand.msg(self, doc[:100])
        try:
            # fix for oletools ignoring ods streams
            ds = 0
            for block in re.findall(rb'\{\\ods([a-zA-Z0-9 \x0a\x0d]{512,})', doc):
                quicksand.msg(self, "RTF ODS size " + str(len(block)))
                self.structure += "rtfods@"+str(ds) +  ","
                quicksand.rtf_block(self, block, str(loc) + "-rtfods@"+str(ds))
                
                ds += 1

            # fix for oletools ignoring datastore streams
            ds = 0
            for block in re.findall(rb'datastore ([a-zA-Z0-9 \x0a\x0d]{512,})', doc):
                quicksand.msg(self, "RTF datastore size " + str(len(block)))
                self.structure += "rtfdatastore@"+ str(ds) + ","
                quicksand.rtf_block(self, block, str(loc) + "-rtfdatastore@"+str(ds))                
                ds += 1

            rt = rtfobj.RtfObjParser(doc)

            rt.parse()
            for obj in rt.objects:
                orig_len = obj.end - obj.start
                quicksand.msg(self, "RTF object size " + str(orig_len))
                quicksand.msg(self, obj.rawdata[:100].hex())
                self.structure += "hexobj" + ","


                if obj.is_package:
                    quicksand.msg (self, "CLASS PACKAGE")
                    quicksand.msg (self, obj.filename)
                    self.structure += str(obj.filename).replace(',', '') + ","
                    self.results['packages'].append({'loc': obj.start, 'filename': obj.filename, 'src_path': obj.src_path, 'temp_path': obj.temp_path})
                    
                if obj.clsid is not None:
                    quicksand.msg (self, obj.clsid)
                    quicksand.msg (self, obj.clsid_desc)
                    quicksand.scan_exploit(self, obj.rawdata, str(loc) + "-rtfcls@" + str(obj.start) + "_" + str(obj.clsid) )
                   
                if obj.olepkgdata != None:
                        quicksand.msg (self, "PACKAGE DATA")
                        self.structure += "rtfpkg@" + str(obj.start) + ","
                        #quicksand.rtf_block(self, obj.olepkgdata, str(loc) + "-rtfpkg@" + str(obj.start))
                        quicksand.scan_exploit(self, obj.olepkgdata, str(loc) + "-rtfpkg@" + str(obj.start))
                        quicksand.scan_exec(self, obj.olepkgdata, str(loc) + "-rtfpkg@" + str(obj.start))
                        if self.capture:
                            self.results['streams'][str(loc) + "-rtfpkg@" + str(obj.start)] = obj.olepkgdata


                elif obj.oledata != None:
                    quicksand.msg (self, "RTFOLE DATA")
                    self.structure += "rtfobjole@" + str(obj.start) + ","
                    #quicksand.rtf_block(self, obj.oledata, str(loc) + "-rtfobjole@" + str(obj.start))
                    quicksand.analyse(self, obj.oledata, str(loc) + "-rtfobjole@" + str(obj.start))
                    if self.capture:
                        self.results['streams'][str(loc) + "-rtfobjole@" + str(obj.start)] = obj.oledata

                else:                       
                    quicksand.rtf_block(self, obj.rawdata, str(loc) + "-rtfobj@" + str(obj.start))

        except Exception as e:
            quicksand.msg(self, e)
            quicksand.msg(self, traceback.format_exc())

    def explode_gfinflate(item):
        for i in range(0,54):
            try:
                #quicksand.msg(self, i)
                unc = zlib.decompress(item[i:], wbits=-zlib.MAX_WBITS)
                #quicksand.msg (self,"gzinflate got " + str(len(unc)))
                return unc
            except:
                None
        return b''

    def explode_gzuncompress(item): #ActiveMime
        for i in range(0,54):
            try:
                return zlib.decompress(item[i:])
            except:
                None
        return b''

    def analyse_mso(self, doc, loc):
        quicksand.scan_exploit(self, doc, str(loc))
        quicksand.scan_exec(self, doc, str(loc))

        for block in re.findall(rb'([a-zA-Z0-9\/+=\x0a\x0d]{1024,})',doc):
            #quicksand.msg (self,block)
            if block[:3] == b'mso':
                decoded = base64.decodebytes(block[3:])
                if decoded[:10] == b'ActiveMime':
                    dc = quicksand.explode_gzuncompress(decoded[10:])
                    quicksand.analyse(self, dc, str(loc) + "-mso-activemime")
                    if self.capture:
                        self.results['streams'][str(loc) + "-mso-activemime"] =  dc
                else:
                    #quicksand.msg (self,decoded)
                    quicksand.analyse(self, decoded, str(loc) + "-mso")
                    if self.capture:
                        self.results['streams'][str(loc) + "-mso"] =  decoded
            else:
                try:
                    decoded = base64.decodebytes(block)
                    if decoded[:10] == b'ActiveMime':
                        dc = quicksand.explode_gzuncompress(decoded[10:])
                        quicksand.analyse(self, dc, str(loc) + "-b64-activemime")
                        if self.capture:
                            self.results['streams'][str(loc) + "-b64-activemime"] =  dc
                    else:
                        quicksand.analyse(self, decoded, str(loc) + "-b64")
                        if self.capture:
                            self.results['streams'][str(loc) + "-b64"] =  decoded
                except:
                    None
                    #quicksand.msg(self, "block didn't decode " + str(block[:10]))



    def analyse_ps(self, doc,loc):
        quicksand.scan_exploit(self, doc,loc)
        quicksand.scan_exec(self, doc,loc)
        i = 0
        for block in re.findall(b'([a-zA-Z0-9\x0a\x0d\x20\x09]*)',doc):
            #quicksand.msg (self,block)
            obj = bytes.fromhex(block)
            quicksand.scan_exploit(self, obj,loc)
            quicksand.scan_exec(self, obj,loc)
            quicksand.analyse(self, obj, str(loc) + "-pshex" + str(i))
            if self.capture:
                self.results['streams'][str(loc) + "-pshex" + str(i)] =  block
            i += 1


    def dobiff(self, excel_stream, data):
        from oletools.thirdparty.oledump.plugin_biff import cBIFF

        try:
            # example code from olevba
            biff_plugin = cBIFF(name=[excel_stream], stream=data, options='-o BOUNDSHEET')
            xlm_macros = biff_plugin.Analyze()
            if "Excel 4.0 macro sheet" in '\n'.join(xlm_macros):
                 quicksand.msg(self, 'Found XLM macros')
                 # get the list of labels, which may contain the "Auto_Open" trigger
                 biff_plugin = cBIFF(name=[excel_stream], stream=data, options='-o LABEL -r LN')
                 xlm_macros += biff_plugin.Analyze()
                 biff_plugin = cBIFF(name=[excel_stream], stream=data, options='-c -r LN')
                 xlm_macros += biff_plugin.Analyze()
                 # we run plugin_biff again, this time to search DCONN objects and get their URLs, if any:
                 # ref: https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros
                 biff_plugin = cBIFF(name=[excel_stream], stream=data, options='-o DCONN -s')
                 xlm_macros += biff_plugin.Analyze()
                 return xlm_macros
        except:
            print('Error when running oledump.plugin_biff, please report to %s' % URL_OLEVBA_ISSUES)



    def analyse_ole(self, doc, loc):
        quicksand.scan_exploit(self, doc,loc)
        quicksand.scan_exec(self, doc,loc)
        hwp = False
        if b'HWP Document' in doc:
            hwp = True

        try: 
                
                ole = olefile.OleFileIO(doc)
                temp = tempfile.NamedTemporaryFile()
                temp.write(doc)
                temp.seek(0)
                
                #handle encryption
                if crypto.is_encrypted(temp.name):
                    try:
                        quicksand.msg (self,"ole file is encrypted")
                        temp.seek(0)
                        passwords = crypto.DEFAULT_PASSWORDS
                        if self.password != None:
                            passwords += [self.password]
                        decrypted_file = crypto.decrypt(temp.name, crypto.DEFAULT_PASSWORDS)
                        if decrypted_file != None:
                            quicksand.msg (self,"ole file decrypted")
                            #print(decrypted_file)
                            buf = open(decrypted_file, "rb")
                            doc = buf.read()
                            #ole = olefile.OleFileIO(doc)
                            myloc = str(loc) + "-oledecrypted"
                            self.structure += "oledecrypted"
                            quicksand.analyse(self, doc, myloc)
                            return

                        temp.close()
                    except Exception as e:
                        quicksand.msg (self, e)
                        quicksand.msg (self, traceback.format_exc())
                
                
                try:
                    meta = ole.get_metadata()
                    if loc == "root":
                    
                        if meta.author != None:
                            self.results['ole_author'] = meta.author.decode("utf-8")
                        if meta.company != None:
                            self.results['ole_company'] = meta.company.decode("utf-8")
                        if meta.last_saved_by != None:
                            self.results['ole_last_saved_by'] = meta.last_saved_by.decode("utf-8")
                        if meta.title != None:
                            self.results['ole_title'] = meta.title.decode("utf-8")
                        if meta.create_time != None:
                            self.results['ole_create_time'] = str(meta.create_time)
                            #self.structure += "olec" + str(meta.create_time) + ","
                        if meta.last_saved_time != None:
                            self.results['ole_last_saved_time'] = str(meta.last_saved_time)
                        
                         
                except Exception as e:
                    quicksand.msg(self, e)
                    quicksand.msg (self,"issue with metatadata")
                    
                if meta.bytes != None:
                    extra = len(doc) - meta.bytes
                    if extra > 1000:
                        #quicksand.msg(self, "WARNING: outside end of OLE structure has " + str(extra) + " bytes")
                        if loc in self.results['results']:
                            self.results['results'][loc].append({'rule': "olefile_end", 'desc': "WARNING: outside end of OLE structure has " + str(extra) + " bytes", 'strings': '', 'type': 'structure'})
                        else:
                            self.results['results'][loc] = [{'rule': "olefile_end", 'desc': "WARNING: outside end of OLE structure has " + str(extra) + " bytes", 'strings': '', 'type': 'structure'}]


                for name in ole.listdir(streams=True, storages=False):
                    quicksand.msg(self, "OLE Stream " + str(name))
                    try:
                        stream = ole.openstream(name)
                        s = stream.read()
                        
                    
                        if type(name) == list:
                            myloc = str(loc) + "-stream-" + str("-".join(name))
                            self.structure += "stream-" + str("-".join(name)) + ","
                            name0 = name[0]
                        else:
                            myloc = str(loc) + "-stream-" + str(name)
                            self.structure += "stream-" + str(name) + ","
                            name0 = name
                        #quicksand.msg (self,s)
                        
                        #handle HWP streams that are zlib compressed
                        #if name0 == 'BinData':
                        if hwp:
                            unc = quicksand.explode_gfinflate(s)
                            if len(unc) > len(s):
                                quicksand.msg(self, "DECOMPRESSED ZLIB STREAM")
                                s = unc
                        
                        if name0 == 'Macros':
                       
                            try:
                                unc = olevba.decompress_stream(s)
                                
                                if len(unc) > len(s):
                                    quicksand.msg(self, "DECOMPRESSED Macro success")
                                    s = unc
                            except:
                                None
 

                        if re.search(binascii.unhexlify(b'504B030414000600'), s, re.IGNORECASE):
                            elements = quicksand.carve(s, binascii.unhexlify(b'504B030414000600'))
                            elements.pop(0)
                            #quicksand.msg (self,"there may this many openxml " + str(len(elements)))

                            directory = 0
                            for i in range(0, len(elements)):
                                r = quicksand.analyse_openxml(self, elements[i], str(loc) + "-" + str(name0) + "-" + "openxml" + str(i))
                                if "negative" in str(r):
                                    r = quicksand.analyse_openxml(self, b''.join(elements[directory : i+1]),str(loc) + "-" + str(name0) + "-" + "openxml" + str(directory) + "-" +str(i))
                                    directory = i+1
                                    if self.capture:
                                        self.results['streams'][str(loc) + "-" + str(name0) + "-" + "openxml" + str(directory) + "-" +str(i)] =  b''.join(elements[directory : i+1])
                                else:
                                    if self.capture:
                                        self.results['streams'][str(loc) + "-" + str(name0) + "-" + "openxml" + str(i)] =  elements[i]
                                    
 
                        if re.search(binascii.unhexlify(b'0000789c'), s, re.IGNORECASE):
                            #quicksand.msg (self,"has gzinflate")
                            elements = quicksand.carve(s, binascii.unhexlify(b'0000789c'))
                            elements.pop(0)
                            for element in elements:
                                #quicksand.msg (self," -element 2 ")
                                #quicksand.msg(self, element)
                                dc = quicksand.explode_gzuncompress(element)
                                quicksand.analyse(self, dc,str(loc)+ "-"  + str(name0) + "-" +"gzinflate")
                                if self.capture:
                                    self.results['streams'][str(loc)+ "-"  + str(name0) + "-" +"gzinflate"] =  dc


                        if re.search(binascii.unhexlify(b'10001110'), s, re.IGNORECASE):
                            #quicksand.msg (self,"has ExOleObjStgCompressedAtom")
                            elements = quicksand.carve(s, binascii.unhexlify(b'10001110'))
                            elements.pop(0)
                            for element in elements:
                                #quicksand.msg (self," -element 3 " + str(len(element)))
                                try:
                                    dc = quicksand.explode_gfinflate(element)
                                    quicksand.analyse(self, dc,str(loc)+ "-"  + str(name0) + "-" + "atom")
                                    if self.capture:
                                        self.results['streams'][str(loc)+ "-"  + str(name0) + "-" + "atom"] =  dc
                                    #quicksand.msg(self, element)
                                except Exception as e:
                                    quicksand.msg(self, e)


                        try:
                            if len(s) > 100 and olefile.isOleFile(s):
                                #quicksand.msg (self,"another OLE")
                                quicksand.analyse_ole(self, s,str(loc) + "-"  + str(name0) + "-ole" + str(i))
                                if self.capture:
                                    self.results['streams'][str(loc) + "-"  + str(name0) + "-ole" + str(i)] =  s
                        except:
                            None
                        #quicksand.msg (self,"scanning ole object")
                        quicksand.scan_exploit(self, s,myloc)
                        quicksand.scan_exec(self, s,myloc)
                        if self.capture:
                            #quicksand.msg(self, "capture ole stream")
                            self.results['streams'][str(myloc)] =  s

                        if name0 == 'Workbook' or name0 == 'Book':
                            quicksand.msg(self, "Excel workbook calling BIFF")
                            macro = self.dobiff(name0, s)
                            if len(macro) > 1:
                                macro_text = bytes("\n".join(macro), 'utf8')
                                quicksand.scan_exploit(self, macro_text,str(myloc) + "-biff")
                                if self.capture:
                                    self.results['streams'][str(myloc)+ "-biff"] =  macro_text


                    except Exception as e:
                        quicksand.msg(self, e)
                        quicksand.msg (self,"stream corrupted " + str(name0))

        except Exception as e:
            quicksand.msg (self,e)
            quicksand.msg(self, "ole failed to parse")
            quicksand.msg (self, traceback.format_exc())

        if re.search(binascii.unhexlify(b'504B030414000600'), doc, re.IGNORECASE):
            ##quicksand.msg(self, "has embedded openxml doc")
            elements = quicksand.carve(doc, binascii.unhexlify(b'504B030414000600'))
            elements.pop(0)
            #quicksand.msg (self,"there may this many openxml " + str(len(elements)))

            directory = 0
            for i in range(0, len(elements)):
                #quicksand.msg(self, element)
                #quicksand.msg (self," -element 1 ")
                r = quicksand.analyse_openxml(self, elements[i], str(loc) + "-openxml" + str(i))
                if "negative" in str(r):
                    #quicksand.msg (self,"range " + str(directory) + " " + str(i))
                    r = quicksand.analyse_openxml(self, b''.join(elements[directory : i+1]),str(loc) + "openxml-" + str(directory) + "-" +str(i))
                    directory = i+1
                    if self.capture:
                        self.results['streams'][str(loc) + "openxml-" + str(directory) + "-" +str(i)] =  b''.join(elements[directory : i+1])
                else:
                    if self.capture:
                        self.results['streams'][str(loc) + "-openxml" + str(i)] =  elements[i]
                    

    def metadata(self) -> None:
        """Populate the results with file metadata."""
        self.results['md5'] = hashlib.md5(self.data).hexdigest()
        self.results['sha1'] = hashlib.sha1(self.data).hexdigest()
        self.results['sha256'] = hashlib.sha256(self.data).hexdigest()
        self.results['sha512'] = hashlib.sha512(self.data).hexdigest()
        self.results['size'] = len(self.data)
        self.results['started'] = time.time()
        self.results['version'] = self.__version__
        self.results['quicksand_exploits.yara'] = os.path.getmtime(self.exploityara)
        self.results['quicksand_exe.yara'] = os.path.getmtime(self.execyara)
        self.results['quicksand_pdf.yara'] = os.path.getmtime(self.pdfyara)
        self.results['header'] = self.data[0:16].hex()
    
    @staticmethod
    def sum_string(item: str) -> str:
        """Calculate a fuzzy hash based on string characters.
        
        Args:
            item: String to hash
            
        Returns:
            Single character hash value
        """
        val = sum(ord(i) for i in item)
        return string.ascii_letters[int(val % len(string.ascii_letters))]
    
    def fuzz_structure(self) -> str:
        """Create a fuzzy hash of the document structure.
        
        Returns:
            Fuzzy hash string
        """
        return ''.join(self.sum_string(element) for element in self.structure.split(',') if element)

    def process(self) -> None:
        """Process the document and generate results."""
        self.metadata()
        self.analyze(self.data, "root")
        
        # Calculate risk level
        self.results['risk'] = "nothing detected"
        self.results['rating'] = 0
        
        if self.results['score'] > 0:
            self.results['risk'] = "risky active content"
            self.results['rating'] = 1
            
        if self.results['score'] >= 5:
            self.results['risk'] = "high risk active content"
            self.results['rating'] = 2
            
        if self.results['exploit'] > 0:
            self.results['risk'] = "risk of exploit"
            self.results['rating'] = 2
            
        if self.results['exploit'] >= 1:
            self.results['risk'] = "high risk of exploit"
            self.results['rating'] = 3
            
        # Finalize the structure and structure hash
        self.structure = self.structure.rstrip(",")
        self.results['structhash'] = hashlib.md5(self.structure.encode("utf-8")).hexdigest()
        self.results['structure'] = self.structure
        self.results['structhash_version'] = "1.0.3"
        self.results['structhash_elements'] = self.structure.count(',') + 1 
        self.results['struzzy'] = self.fuzz_structure()
        
        # Record completion time
        self.results['finished'] = time.time()
        self.results['elapsed'] = self.results['finished'] - self.results['started']

    def analyze(self, doc: bytes, loc: str) -> None:
        """Analyze document bytes to detect exploits.
        
        Args:
            doc: Binary document data to analyze
            loc: Location identifier for reporting
        """
        doc_type = self.check_header(doc)
        self.msg(f"{doc_type} SCAN {loc}")
        self.structure += f"{doc_type}:{loc},"
        
        if loc == "root":
            self.results['type'] = doc_type

        # Process the document according to its type
        if doc_type == "ole":
            self.analyse_ole(doc, loc)
        elif doc_type == "openxml":
            self.analyse_openxml(doc, loc)
        elif doc_type == "rtf":
            self.analyse_rtf(doc, loc)
        elif doc_type == "mso":
            self.analyse_mso(doc, loc)
        elif doc_type == "pdf":
            self.analyse_pdf(doc, loc)
        elif doc_type == "ps":
            self.analyse_ps(doc, loc)
        else:
            # For unknown types, just scan for exploits
            self.scan_exploit(doc, loc)
            self.scan_exec(doc, loc)
            
    # Keep the original method name for backward compatibility
    analyse = analyze

    @staticmethod
    def check_header(doc: bytes) -> str:
        """Determine document type based on header bytes.
        
        Args:
            doc: Binary document data
            
        Returns:
            String indicating the detected file type
        """
        if re.search(binascii.unhexlify('5c5C7274'), doc[0:256], re.IGNORECASE):
            return "rtf"
        elif doc[:4] == binascii.unhexlify(b'd0cf11e0'):
            return "ole"
        elif re.search(b'\x50\x4B\x03\x04\x14\x00', doc, re.IGNORECASE): # should be deeper
            return "openxml"
        elif doc[:2] == b'PK':
            return "zip"
        elif re.search(b'%PDF', doc[0:1024], re.IGNORECASE):
            return "pdf"
        elif re.search(rb'ns.adobe.com\/xdp', doc[0:1024], re.IGNORECASE):
            return "xdp"
        elif re.search(b'MIME-Version', doc[0:256], re.IGNORECASE):
            return "mso"
        elif re.search(b'xml', doc[0:256], re.IGNORECASE):
            return "mso"
        elif doc[0:4] == b'%!PS':
            return "ps"
        else:
            return "data"
            
    # Keep the original method name for backward compatibility
    checkHeader = check_header

