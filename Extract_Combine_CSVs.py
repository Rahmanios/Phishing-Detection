import pandas as pd


#reading and selecting and saving the Phish URL's
Phish_csv = pd.read_csv("Content/CSVs/Phish_verified_online.csv")###
Phish_extract = Phish_csv.sample(n=10000, random_state=42)
Phish_URL = Phish_extract[["url"]]
Phish_URL.to_csv("Content/CSVs/phish_urls_extracted_10000.csv", index=False)

#reading and selecting and saving the Legit URL's
Legit_csv = pd.read_csv("Content/CSVs/Legit_top-1m.csv", header=None)
Legit_extract = Legit_csv.sample(n=10000, random_state=42)
Legit_URL = Legit_extract[1]
Legit_URL = "https://www." + Legit_URL
Legit_URL.to_csv("Content/CSVs/Legit_urls_extracted_10000.csv", index=False, header=False)

#combined_csvs = pd.concat([Legit_URL, Phish_URL])
#combined_csvs.to_csv("Content/CSVs/Phish_legit_combined.csv", index=False)


                            ##### TESTING
#Extracting 100 rndom phish urls to test and practice the feature extraction results
Phish_csv = pd.read_csv("Content/CSVs/Phish_verified_online.csv")###
Phish_extract = Phish_csv.sample(n=100, random_state=42)
Phish_URL = Phish_extract[["url"]]
Phish_URL.to_csv("Content/CSVs/Test_CSVs/PHISH_urls_FOR_TEST.csv", index=False)


Legit_csv = pd.read_csv("Content/CSVs/Legit_top-1m.csv", header=None)
Legit_extract = Legit_csv.sample(n=100, random_state=42)
Legit_URL = Legit_extract[1]
Legit_URL = "https://www." + Legit_URL
Legit_URL.to_csv("Content/CSVs/Test_CSVs/LEGIT_urls__FOR_TEST.csv", index=False, header=False)


print("Phish_Extract")
print(Phish_URL.head())
print("---------------------------------")
print("LEGIT")
print(Legit_URL.head())
print("---------------------------------")
