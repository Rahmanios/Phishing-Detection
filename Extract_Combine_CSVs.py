import pandas as pd


#reading and selecting and saving the Phish URL's
Phish_csv = pd.read_csv("Content/CSVs/Phish_verified_online.csv")###
Phish_extract = Phish_csv.sample(n=10000, random_state=12)
Phish_URL = Phish_extract[["url"]]
Phish_URL.to_csv("Content/CSVs/phish_urls_extracted_10000.csv", index=False)

#reading and selecting and saving the Legit URL's
Legit_csv = pd.read_csv("Content/CSVs/Legit_top-1m.csv", header=None)
Legit_extract = Legit_csv.sample(n=10000, random_state=12)
Legit_URL = Legit_extract[1]
Legit_URL.to_csv("Content/CSVs/Legit_urls_extracted_10000.csv", index=False, header=False)

combined_csvs = pd.concat([Legit_URL, Phish_URL])
combined_csvs.to_csv("Content/CSVs/Phish_legit_combined.csv", index=False)



print("Phish_Extract")
print(Phish_URL.head())
print("---------------------------------")
print("LEGIT")
print(Legit_URL.head())
print("---------------------------------")
