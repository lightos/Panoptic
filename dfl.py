#!/usr/bin/env python

"""
Search default file locations on Windows, Linux or Mac.
"""

class DFL:
	"""
	Contains all the functionality to run DFL.
	"""
	def __init__(self):
		"""
		Initiates the DFL object.
		"""
		self.software = ""
		self.classification = ""
		self.operating_system = ""
		self.file_attributes = {}
		
	def parse_file(self):
		"""
		Main function for DFL.
		"""	
		for file_location in open("file_locations.txt"):
			if file_location[0] == "[":
				self.operating_system =  file_location[1:-1]
				continue
			elif file_location[0] == "#":
				self.software =  file_location[1:]
				continue
			elif file_location[0] == "*":
				self.classification =  file_location[1:]
				continue

			self.file_attributes["OS"] = self.operating_system
			self.file_attributes["software"] = self.software
			self.file_attributes["classification"] = self.classification
			self.file_attributes["location"] = file_location
			
			print self.file_attributes
			
	
def main():
	dfl = DFL()
	dfl.parse_file()
	
if __name__ == "__main__": main()