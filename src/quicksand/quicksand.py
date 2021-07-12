#!/usr/bin/env python
###
### QuickSand 2: Python3 Version Copyright (c) 2021 @tylabs
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
import os.path
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



class quicksand:
    __version__ = '2.0.12'
    __author__ = "Tyler McLellan"
    __copyright__ = "Copyright 2021, @tylabs"
    __license__ = "MIT"
    
    try:
        exploityara = str(os.path.dirname(__file__)) + '/quicksand_exploits.yara'
        execyara = str(os.path.dirname(__file__)) + '/quicksand_exe.yara'
        pdfyara = str(os.path.dirname(__file__)) + '/quicksand_pdf.yara'

    except:
        exploityara = 'quicksand_exploits.yara'
        execyara = 'quicksand_exe.yara'
        pdfyara = 'quicksand_pdf.yara'
    
    def msg(self, m):
        if self.debug:
            print(str(time.time()) + ": " + str(m))

    def readFile(self, filename):
        try:
            f = open(filename, "rb")
            doc = f.read()
            f.close()
            return doc
        except:
            self.msg("ERROR: file not found")
            return b''
    
    def readDir(directory,capture=False,strings=True, debug=False, timeout=0, exploityara=None, execyara=None,pdfyara=None, password=None):
        out = {}
        for f in listdir(directory):
            fname = join(directory, f)
            if isfile(fname):
                #print (fname)
                q = quicksand(fname,capture=capture,strings=strings, debug=debug, timeout=timeout, exploityara=exploityara, execyara=execyara,pdfyara=pdfyara,password=password)
                q.process()
                out[fname] = q.results
        return out


    def mapStructure(self, parent, loc):
        None

    def __init__(self, data, capture=False,strings=True, debug=False, timeout=0, exploityara=None, execyara=None,pdfyara=None, password=None):
        self.results = {'results' : {}}
        self.structure = {}

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
        self.structure = ""
        if self.capture:
            self.results['streams'] = {}
        

        if os.path.isfile(data):
            self.results['filename'] = data
            self.data = quicksand.readFile(self, data)
        else:
            self.results['filename'] = None
            self.data = data
        if exploityara != None:
            self.exploityara = exploityara
        if execyara != None:
            self.execyara = execyara
        if pdfyara != None:
            self.pdfyara = pdfyara
            
        self.exploitrules = yara.compile(filepath=self.exploityara)
        self.execrules = yara.compile(filepath=self.execyara)
        self.pdfrules = yara.compile(filepath=self.pdfyara)
           


    def carve(item, separator):
        return [separator+e for e in item.split(separator) if e]


    def scan_exploit(self, item, loc):
        matches = self.exploitrules.match(data=item)

        if matches:
            for m in matches:
                rtype = "exploit"
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
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre})
                    else:
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre})
                else:
                    if self.strings:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre}]
                    else:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre}]
                        
                quicksand.msg(self, "YARA EXPLOIT: " + str(loc)+ ":" + str(m.rule))
                #quicksand.msg(self, m.strings)



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
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre})
                    else:
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre})
                else:
                    if self.strings:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre}]
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
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre})
                    else:
                        self.results['results'][loc].append({'rule': m.rule, 'desc': desc, 'type': rtype, 'mitre': mitre})
                else:
                    if self.strings:
                        self.results['results'][loc] = [{'rule': m.rule, 'desc': desc, 'strings': m.strings, 'type': rtype, 'mitre': mitre}]
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
            for block in re.findall(b'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))',doc):
                if len(block[2]) != 0:
                    num = int(block[2])
                    gen = int(block[3])
                    quicksand.msg (self,"obj " + str(num) + " " + str(gen))
                    self.structure += str(num) + "-" + str(gen) + ","
                else:
                    self.structure += block[5].decode("utf-8")  + ","
                    quicksand.msg (self,"obj " + str(block[5].decode("utf-8")) )

            # validate that there's no hidden pdf objects by parsing them out
            for block in re.findall(b'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj(\x0a|\x0d|\x20)<<[^>]{1,200}\x2fFilter)',doc):
                quicksand.msg(self, block)
                if self.timeout > 0 and time.time() - self.results['started'] > self.timeout:
                    self.results['skip'] = 1
                    continue

                #for block in re.findall(b'((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))',doc):
                #quicksand.msg (self,str(time.time()) + " " + str(block))
                if block[2]:
                    num = int(block[2])
                    gen = int(block[3])
                    quicksand.msg (self,"stream " + str(num) + " " + str(gen))
                    
                    try:
                        raw_obj = pdf.locate_object(num, gen)

                        obj = pdf.build(raw_obj)
                    except Exception as e:
                        quicksand.msg(self, e)
                        
                    try:
                        if type(obj) == pdfreader.types.objects.StreamBasedObject:
                            #quicksand.msg(self, "scan stream " + str (obj.get('Filter')) + " " + str(len(obj.filtered)))
                            #quicksand.scan_pdf(self, obj.data,str(loc) + "-pdf_" + str(num) + "_" + str(gen))
                            quicksand.scan_pdf(self, obj.filtered,str(loc) + "-pdf_" + str(num) + "_" + str(gen))
                            if self.capture:
                                self.results['streams'][str(loc) + "-pdf_" + str(num) + "_" + str(gen)] = obj.filtered
                        #else:
                            #quicksand.msg(self, obj)
                    except Exception as e:
                        quicksand.msg(self, e)
            
                else:
                    #quicksand.msg (self,"special " + str(block[5].decode()) )
                    None
        except Exception as e:
            
            quicksand.msg(self, "Error parsing PDF due to " + str(e))
            

            if loc in self.results['results']:
                self.results['results'][loc].append({'rule': "pdf_malformed", 'desc': "WARNING: PDF is malformed", 'strings': '', 'type': 'structure'})
            else:
                self.results['results'][loc] = [{'rule': "pdf_malformed", 'desc': "WARNING: PDF is malformed", 'strings': '', 'type': 'structure'}]
           


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

        quicksand.msg(self, "RTF obj size " + str(len(obj)))
        if self.capture:
            self.results['streams'][loc] = obj
        
        #scan objects
        quicksand.scan_exploit(self, obj, str(loc))
        quicksand.scan_exec(self, obj, str(loc))
        #extract OLE files
        if re.search(binascii.unhexlify(b'd0cf11e0'), obj, re.IGNORECASE):
            quicksand.msg(self, str(loc) + "has embedded ole doc")
            elements = quicksand.carve(obj, binascii.unhexlify(b'd0cf11e0'))
            elements.pop(0)
            quicksand.msg (self,"there may this many ole " + str(len(elements)))

            directory = 0
            for i in range(0, len(elements)):
                #quicksand.msg(self, elements[i])
                newloc = "ole" + str(i)
                self.structure += str(newloc) + ","

                r = quicksand.analyse_ole(self, elements[i], str(loc) + "-" + str(newloc))
                if self.capture:
                    self.results['streams'][str(loc) + str(newloc)] = elements[i]

                if "negative" in str(r) and len(elements) > 1:
                    quicksand.msg (self,"range " + str(directory) + " " + str(i))
                    r = quicksand.analyse_ole(self, b''.join(elements[directory : i+1]),str(loc) + "-oleg" + str(directory) + "-" + str(i))

                    directory = i+1
                    if self.capture:
                        self.results['streams'][str(loc) + "-oler" + str(directory) + "-" +str(i)] = b''.join(elements[directory : i+1])
                    else:
                        if self.capture:
                            self.results['streams'][str(loc) + "-olea-" + str(i)] =  elements[i]

        #extract openxml zip
        if re.search(binascii.unhexlify(b'504B030414000600'), obj, re.IGNORECASE):
            quicksand.msg(self, "has embedded openxml doc")
            elements = quicksand.carve(obj, binascii.unhexlify(b'504B030414000600'))
            elements.pop(0)
            #quicksand.msg (self,"there may this many openxml " + str(len(elements)))

            directory = 0
            for i in range(0, len(elements)):
                quicksand.msg(self, element)
                quicksand.msg (self," -element 1 ")
                newloc = "openxml" + str(i)
                self.structure += str(newloc) + ","
                r = quicksand.analyse_openxml(self, elements[i], str(loc) + "-" + str(newloc))
                if self.capture:
                    self.results['streams'][str(loc) + str(newloc)] = elements[i]

                if "negative" in str(r) and len(elements) > 1:
                    quicksand.msg (self,"range " + str(directory) + " " + str(i))
                    r = quicksand.analyse_openxml(self, b''.join(elements[directory : i+1]),str(loc) + "-openxmlg" + str(directory) + "-" +str(i))
                    directory = i+1
                    if self.capture:
                        self.results['streams'][str(loc) + "-openxmlr" + str(directory) + "-" +str(i)] = b''.join(elements[directory : i+1])
                else:
                    if self.capture:
                        self.results['streams'][str(loc) + "-openxmla" + str(i)] = elements[i]


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

        for block in re.findall(b'([a-zA-Z0-9\/+=\x0a\x0d]{1024,})',doc):
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
                    

    def metadata(self):
        self.results['md5'] = hashlib.md5(self.data).hexdigest()
        self.results['sha1'] = hashlib.sha1(self.data).hexdigest()
        self.results['sha256'] = hashlib.sha256(self.data).hexdigest()
        self.results['sha512'] = hashlib.sha512(self.data).hexdigest()
        self.results['size'] = len(self.data)
        self.results['started'] = time.time()
        self.results['version'] = quicksand.__version__
        self.results['quicksand_exploits.yara'] = os.path.getmtime(self.exploityara)
        self.results['quicksand_exe.yara'] = os.path.getmtime(self.execyara)
        self.results['quicksand_pdf.yara'] = os.path.getmtime(self.pdfyara)
        self.results['header'] = self.data[0:16].hex()
       
    
    def sumString(item):
        valid = []
        val = 0
        for i in item:
            #quicksand.msg(self, i)
            val += ord(i)
            #quicksand.msg (self,val)
        #quicksand.msg (self,"sum " + str(val) + " " + string.ascii_letters[int(val % len(string.ascii_letters))])
        return string.ascii_letters[int(val % len(string.ascii_letters))]
    
    def fuzzStructure(self):
        out = ''
        for element in self.structure.split(','):
            #quicksand.msg(self, element)
            out += quicksand.sumString(element)
        return out

    def process(self):
        quicksand.metadata(self)
        quicksand.analyse(self, self.data, "root")
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
        if self.results['exploit'] >= 3:
            self.results['risk'] = "high risk of exploit"
            self.results['rating'] = 3
        self.structure = self.structure.rstrip(",")
        self.results['structhash'] = hashlib.md5(self.structure.encode("utf-8")).hexdigest()
        self.results['structure'] = self.structure
        self.results['structhash_version'] = "1.0.3"
        self.results['structhash_elements'] = self.structure.count(',')+1 
        self.results['struzzy'] = quicksand.fuzzStructure(self)
        self.results['finished'] = time.time()
        self.results['elapsed'] = self.results['finished'] - self.results['started']
        

    def analyse(self, doc, loc):

        type = quicksand.checkHeader(doc)
        quicksand.msg(self, str(type) + " SCAN " + str(loc))
        self.structure += str(type) + ":" + str(loc) + ","
        
        if loc == "root":
            self.results['type'] = type

        if type == "ole":
            quicksand.analyse_ole(self, doc, loc)
        elif type == "openxml":
            quicksand.analyse_openxml(self, doc, loc)
        elif type == "rtf":
            quicksand.analyse_rtf(self, doc, loc)
        elif type == "mso":
            quicksand.analyse_mso(self, doc, loc)
        elif type == "pdf":
            quicksand.analyse_pdf(self, doc, loc)
        elif type == "ps":
            quicksand.analyse_ps(self, doc, loc)
        else:
            quicksand.scan_exploit(self, doc, loc)
            quicksand.scan_exec(self, doc, loc)



    def checkHeader(doc):
        #quicksand.msg(self, doc[0:256])
        if re.search(binascii.unhexlify('5c5C7274'), doc[0:256], re.IGNORECASE):
            return "rtf"
        elif doc[:4] == binascii.unhexlify(b'd0cf11e0'):
            return "ole"
        elif  re.search(b'\x50\x4B\x03\x04\x14\x00', doc, re.IGNORECASE): # should be deeper
            return "openxml"
        elif doc[:2] == b'PK':
            return "zip"
        elif re.search(b'%PDF', doc[0:1024], re.IGNORECASE):
            return "pdf"
        elif re.search(b'ns.adobe.com\/xdp', doc[0:1024], re.IGNORECASE):
            return "xdp"
        elif re.search(b'MIME-Version', doc[0:256], re.IGNORECASE):
            return "mso"
        elif re.search(b'xml', doc[0:256], re.IGNORECASE):
            return "mso"
        elif doc[0:4] == b'%!PS':
            return "ps"
        else:
            return "data"

