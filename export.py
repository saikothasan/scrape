import csv
import logging
import sqlite3

class Exporter:
    """Handles exporting data from the database to a CSV file."""

    def __init__(self, db_file):
        self.db_file = db_file

    def export_to_csv(self, columns, output_file_path):
        """
        Exports specified columns from the database to a CSV file.

        Args:
            columns (list): A list of column names to export.
            output_file_path (str): The path to save the CSV file.
        """
        if not columns:
            raise ValueError("No columns specified for export.")

        logging.info(f"Exporting columns {columns} to {output_file_path}")

        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = f"SELECT {', '.join(columns)} FROM scraped_pages"
                
                cursor.execute(query)
                
                with open(output_file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    for row in cursor:
                        writer.writerow(row)
            
            logging.info("Export completed successfully.")
            return True
        except sqlite3.Error as e:
            logging.error(f"Database error during export: {e}")
            return False
        except IOError as e:
            logging.error(f"File write error during export: {e}")
            return False
