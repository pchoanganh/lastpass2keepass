# lastpass2keepass
# Supports:
# Keepass XML - keepassxml
# USAGE: python lastpass2keepass.py exportedTextFile
# The LastPass Export format;
# url,username,password,1extra,name,grouping(\ delimited),last_touch,launch_count,fav

import sys, csv, time, datetime, itertools, re # Toolkit
import xml.etree.ElementTree as ET # Saves data, easier to type

# Strings

fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________\n"

def formattedPrint(string):
    print lineBreak
    print string
    print lineBreak
       
# Files
# Check for existence/read/write.

try:
    inputFile = sys.argv[1]
except:
    formattedPrint("USAGE: python lastpass2keepass.py exportedTextFile")
    sys.exit()
    
try:
	f = open(inputFile)
except IOError:
	formattedPrint("Cannot read file: '%s' Error: '%s'" % (inputFile, fileError) )
	sys.exit()
	
# Create XML file.
outputFile = inputFile + ".export.xml"

try:
    open(outputFile, "w").close() # Clean.
    w = open(outputFile, "a")
except IOError:
    formattedPrint("Cannot write to disk... exiting. Error: '%s'" % (fileError) )
    sys.exit()

# Parser
# Parse w/ delimter being comma, and entries separted by newlines
reader = csv.reader(f, delimiter=',', quotechar='"')

# Create a list of the entries, allow us to manipulate it.
# Can't be done with reader object.

allEntries = []

for x in reader:
    allEntries.append(x)

allEntries.pop(0) # Remove LP format string.

f.close() # Close the read file.

# Keepass XML generator
   
# Add doctype to head, clear file.
w.write("<!DOCTYPE KEEPASSX_DATABASE>")

# Generate Creation date
# Form current time expression.
now = datetime.datetime.now()
formattedNow = now.strftime("%Y-%m-%dT%H:%M")

# Initialize tree
# build a tree structure
page = ET.Element('database')
doc = ET.ElementTree(page)

# Dictionary of failed entries
failed = {}
    
formattedPrint("DEBUG of '%s' file conversion to the KeePassXML format, outputing to the '%s' file." %(inputFile,outputFile))
    
# A dictionary, organising the categories.
resultant = {}
    
# Parses allEntries into a resultant.
for entry in allEntries:
    try:
        categories = re.split(r"[/\\]",entry[5]) # Grab final category.
        
        for x in categories:
            resultant.setdefault(categories.pop(), []).append(entry) # Sort by categories.
    except:
        # Catch illformed entries         
        # Grab entryElement position
        p = allEntries.index(entry) + 2
        failed[p] = [",".join(entry)]
        
        print "Failed to format entryElement at line %s" % (p)

# Initilize and loop through all entries
for category, categoryEntries in resultant.iteritems():

	# Create head of group elements
    headElement = ET.SubElement(page, "group")
    ET.SubElement(headElement, "title").text = str(category)
    ET.SubElement(headElement, "icon").text = "0" # Lastpass does not retain icons.
    
    for entry in categoryEntries: 
    # entryElement information
        try:
            # Each entryElement
            entryElement = ET.SubElement(headElement, "entry")
            # entryElement tree
            ET.SubElement(entryElement, 'title').text = str(entry[4]).decode("utf-8")
            ET.SubElement(entryElement, 'username').text = str(entry[1]).decode("utf-8")
            ET.SubElement(entryElement, 'password').text = str(entry[2]).decode("utf-8")
            ET.SubElement(entryElement, 'url').text = str(entry[0]).decode("utf-8")
            ET.SubElement(entryElement, 'comment').text = str(entry[3]).decode("utf-8")
            ET.SubElement(entryElement, 'icon').text = "0"
            ET.SubElement(entryElement, 'creation').text = formattedNow
            ET.SubElement(entryElement, 'lastaccess').text = str(entry[6]).decode("utf-8")
            ET.SubElement(entryElement, 'lastmod').text = str(entry[7]).decode("utf-8")
            ET.SubElement(entryElement, 'expire').text = "Never"
        except:
            # Catch illformed entries          
            # Grab entry position
            p = allEntries.index(entry) + 2
            failed[p] = [",".join(entry)]
            print "Failed to format entry at line %d" %(p)

# Check if it was a clean conversion.
if len(failed) != 0:
    # Create a failed list.
    failedList = ["%d : %s" %(p, str(e[0]).decode("utf-8")) for p, e in failed.items()]
    formattedPrint("The conversion was not clean.")
    print "You need to manually import the below entries from the '%s' file, as listed by below." %(inputFile)
    formattedPrint("Line Number : entryElement")
    for x in failedList:
        print x

# Write out tree
# wrap it in an ElementTree instance, and save as XML
doc.write(w)
w.close()

print lineBreak
print "\n'%s' has been succesfully converted to the KeePassXML format." %(inputFile)
print "Converted data can be found in the '%s' file.\n" %(outputFile)
print lineBreak
