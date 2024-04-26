import pandas as pd

def read_csv_with_pandas(filename):
    """ Read a CSV file using Pandas where the first line is the header """
    # Load the CSV into a DataFrame
    data_types = {
        'func_name': str,
        'vul_type': str,
        'true_label': int,
        'pred_label': int
    }

    # Read the CSV file with specified data types
    df = pd.read_csv(filename, dtype=data_types)
    print(df.head())

    df['correct_prediction'] = df['true_label'] == df['pred_label']
    grouped = df.groupby('vul_type')['correct_prediction'].agg([("correct_count", "sum"), ("total_count", "count")])

    grouped['accuracy'] = grouped['correct_count'] / grouped['total_count']
    # Find the highest and lowest accuracy
    max_accuracy = grouped['accuracy'].idxmax()
    min_accuracy = grouped['accuracy'].idxmin()

    print(grouped)
    print(f"Highest Accuracy Group: {max_accuracy} with Accuracy: {grouped.loc[max_accuracy, 'accuracy']:.2f}")
    print(f"Lowest Accuracy Group: {min_accuracy} with Accuracy: {grouped.loc[min_accuracy, 'accuracy']:.2f}")

    # Calculate overall accuracy for the entire DataFrame
    overall_accuracy = df['correct_prediction'].mean()
    print(f"Overall Accuracy: {overall_accuracy:.2f}")


    # print(matches[True])
    # # Sum the True values to get the number of matches
    
    # print(num_matches)
    return

# Example usage
def main():
    csv_file_path = 'cleaned_results.csv'  # Replace with your CSV file path
    read_csv_with_pandas(csv_file_path)


if __name__ == "__main__":
    main()
