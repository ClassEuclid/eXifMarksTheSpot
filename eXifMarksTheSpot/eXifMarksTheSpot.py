import os
import hashlib
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
'''
Script Name : eXifMarksTheSpot

Description:
------------
eXifMarksTheSpot scans a user-specified folder for JPEG images, extracts GPS metadata from EXIF tags if available,
and computes the MD5 hash for each file. The results are saved into:
- an HTML report (clickable links to images, GPS coordinates, hashes)
- a KML file for visualization in mapping tools (e.g. Google Earth)

This tool is designed for presentations,
providing clear, visual  of where images were captured.

Author: Class Euclid

Version: 2.1.0
Date: 2025-07-12

Dependencies:
    - pillow
    - customtkinter
    - tkinter
    - geopy (optional for future enhancements)
    - lxml (optional for future advanced KML handling)

References/Credit:
    - https://github.com/ianare/exif-samples/tree/master/jpg/gps

Todo:
------
- Add image thumbnails to HTML report
- Add support for video EXIF metadata
- Implement time/date filtering
- Export additional EXIF details (camera model, timestamp, etc.)
- Add CSV export option for integration with other tools
- Implement map animation features for presentation

'''


def md5_hash_validate(file_path):
    """
    Computes the MD5 hash of a file.
    Allows for faster searching or triaging and/or duplicates
    
    Args:
        file_path (str): Path to the file.

    Returns:
        str: The MD5 hash as a hex string, or "Error" if calculation fails.
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print("Error computing MD5 for file:", file_path)
        print("Exception message:", e)
        return "Error"
    
    

def extract_gps_coords(image_path):
    """
    Extracts GPS latitude and longitude from an image's EXIF metadata if available.

    This function reads the EXIF GPS tags to determine where an image was taken,
    which is crucial for location based artifacts.

    Args:
        image_path (str): Full path to the image file (JPEG/JPG).

    Returns:
        tuple or None:
            - (latitude, longitude) as decimal degrees if GPS data is found.
            - None if GPS data is not present or an error occurs.
    """
    
    
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            return None

        gps_info = {}
        for tag, value in exif_data.items():
            decoded_tag = TAGS.get(tag, tag)
            if decoded_tag == "GPSInfo":
                for gps_tag in value:
                    sub_decoded_tag = GPSTAGS.get(gps_tag, gps_tag)
                    gps_info[sub_decoded_tag] = value[gps_tag]

        if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
            lat_deg, lat_min, lat_sec = gps_info['GPSLatitude']
            lon_deg, lon_min, lon_sec = gps_info['GPSLongitude']

            latitude = lat_deg + (lat_min / 60.0) + (lat_sec / 3600.0)
            longitude = lon_deg + (lon_min / 60.0) + (lon_sec / 3600.0)

            if gps_info.get('GPSLatitudeRef') == 'S':
                latitude = -latitude
            if gps_info.get('GPSLongitudeRef') == 'W':
                longitude = -longitude

            return latitude, longitude
        return None
    except Exception as e:
        print(f"Error reading EXIF data for {image_path}: {e}")
        return None
    
    
    

def kml_file_generation(kml_file, gps_data):
    """
    Generates a KML file containing placemarks for images with GPS coordinates.

    This file can be opened in mapping applications like Google Earth
    to visualize locations where photos were captured.

    Args:
        kml_file (str): Full path to the KML output file to be created.
        gps_data (list of tuples):
            Each tuple contains:
                - filename (str): Name of the image file.
                - latitude (float): Latitude in decimal degrees.
                - longitude (float): Longitude in decimal degrees.

    """
    
    
    with open(kml_file, 'w') as kml:
        kml.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        kml.write("<kml xmlns='http://www.opengis.net/kml/2.2'>\n")
        kml.write("  <Document>\n")

        for filename, lat, lon in gps_data:
            kml.write("    <Placemark>\n")
            kml.write(f"      <name>{filename}</name>\n")
            kml.write("      <Point>\n")
            kml.write(f"        <coordinates>{lon},{lat},0</coordinates>\n")
            kml.write("      </Point>\n")
            kml.write("    </Placemark>\n")

        kml.write("  </Document>\n")
        kml.write("</kml>\n")
    print(f"KML file saved: {kml_file}")

def results_directory(directory_path, output_file, kml_file):
    """
    Processes all JPEG/JPG images in selected directory

    For each image:
        - Extracts GPS coordinates (if available).
        - Calculates the MD5 hash.
        - Appends data to an HTML report with clickable image links.

    Also generates a KML file to map all geotagged images.
    Both are saved as the name entered by user

    Args:
        directory_path (str): Path to the folder containing images.
        output_file (str): Path to save the HTML output report.
        kml_file (str): Path to save the generated KML file.
    """
    
    gps_data_list = []

    with open(output_file, 'w', encoding='utf-8') as out_file:
        out_file.write("<html><head><title>Image Metadata</title></head><body>")
        out_file.write("<h2>Image Metadata Report</h2>")
        out_file.write("<table border='1' cellspacing='0' cellpadding='5'>")
        out_file.write("<tr><th>File Name</th><th>Latitude</th><th>Longitude</th><th>MD5 Hash</th></tr>")

        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)

            if os.path.isfile(filepath) and filename.lower().endswith(('.jpg', '.jpeg')):
                gps_coords = extract_gps_coords(filepath)
                md5_hash = md5_hash_validate(filepath)

                file_link = f"<a href='file:///{filepath.replace(os.sep, '/')}'> {filename} </a>"

                if gps_coords:
                    lat, lon = gps_coords
                    gps_data_list.append((filename, lat, lon))
                    line = f"<tr><td>{file_link}</td><td>{lat}</td><td>{lon}</td><td>{md5_hash}</td></tr>"
                else:
                    line = f"<tr><td>{file_link}</td><td>No GPS Data</td><td>-</td><td>{md5_hash}</td></tr>"

                out_file.write(line)
                print(f"Processed: {filename}, MD5: {md5_hash}, GPS: {gps_coords if gps_coords else 'No GPS Data'}")

        out_file.write("</table></body></html>")

    if gps_data_list:
        kml_file_generation(kml_file, gps_data_list)

# GUI 

class ImageForensicsApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("eXifMarksTheSpot")
        self.geometry("700x400")
        # simple appearance model for gui
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # Input directory
        self.input_label = ctk.CTkLabel(self, text="Select Input Directory:")
        self.input_label.pack(pady=(20,5))

        self.input_entry = ctk.CTkEntry(self, width=500)
        self.input_entry.pack(pady=5)

        self.input_button = ctk.CTkButton(self, text="Browse", command=self.browse_input_directory)
        self.input_button.pack(pady=5)

        # Output HTML file
        self.output_label = ctk.CTkLabel(self, text="Select Output Directory for Results:")
        self.output_label.pack(pady=(20,5))

        self.output_entry = ctk.CTkEntry(self, width=500)
        self.output_entry.pack(pady=5)

        self.output_button = ctk.CTkButton(self, text="Browse", command=self.browse_output_file)
        self.output_button.pack(pady=5)

        # Run Button
        self.run_button = ctk.CTkButton(self, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=(40, 10))

    def browse_input_directory(self):
        directory = filedialog.askdirectory(title="Select Input Directory")
        if directory:
            self.input_entry.delete(0, ctk.END)
            self.input_entry.insert(0, directory)

    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Output HTML File",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")]
        )
        if file_path:
            self.output_entry.delete(0, ctk.END)
            self.output_entry.insert(0, file_path)

    def run_analysis(self):
        input_dir = self.input_entry.get()
        output_html = self.output_entry.get()

        if not input_dir or not output_html:
            messagebox.showerror("Error", "Please select both input directory and output file.")
            return

        kml_filename = os.path.splitext(os.path.basename(output_html))[0] + ".kml"
        kml_file_path = os.path.join(os.path.dirname(output_html), kml_filename)

        try:
            results_directory(input_dir, output_html, kml_file_path)
            messagebox.showinfo("Success", f"HTML report saved to:\n{output_html}\n\nKML saved to:\n{kml_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

if __name__ == "__main__":
    app = ImageForensicsApp()
    app.mainloop()
