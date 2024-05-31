import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score


DEFAULT_QUERY_MODEL = "gpt-4-turbo"

def calculate_all_results(filename):
    # calculate the stats for all cwe vulnerability types at once
    # Load the CSV into a DataFrame
    data_types = {
        'func_name': str,
        'vul_type': str,
        'true_label': int,
        'pred_label': int
    }

    # Read the CSV file with specified data types
    df = pd.read_csv(filename, dtype=data_types)

    # Group by 'vul_type' and calculate precision, recall, average, and accuracy
    results = df.groupby('vul_type').apply(lambda group: pd.Series({
        'accuracy': accuracy_score(group['true_label'], group['pred_label']),
        'precision': precision_score(group['true_label'], group['pred_label'], zero_division=0),
        'recall': recall_score(group['true_label'], group['pred_label'], zero_division=0)
    }))

    # Identify the groups with the highest and lowest accuracy
    highest_accuracy_group = results['accuracy'].idxmax()
    lowest_accuracy_group = results['accuracy'].idxmin()

    print(results)
    print(f"Highest accuracy group: {highest_accuracy_group} with accuracy {results.loc[highest_accuracy_group, 'accuracy']:.3f}")
    print(f"Lowest accuracy group: {lowest_accuracy_group} with accuracy {results.loc[lowest_accuracy_group, 'accuracy']:.3f}")
    
    # Calculate overall avg accuricies for all group
    average_accuracy = results['accuracy'].mean()
    print(f"Overall Accuracy: {average_accuracy:.2f}")

    return

def calculate_target_stats(
    experiment_name,
    csv_file_path,
    output_file,
    sig_fig=3
):
    target_file_format = {
        'func_name': str,
        'pred_label': int,
        'true_label': int
    }
    # Read the CSV file into a DataFrame
    df = pd.read_csv(csv_file_path, dtype=target_file_format)
    df.columns = df.columns.str.strip()

    # Clean and convert columns to the appropriate data types
    for column in ['pred_label', 'true_label']:
        # check for string hallucination
        df[column] = pd.to_numeric(df[column], errors='coerce')
        if df[column].isnull().any():
            print(f"Warning: Non-convertible values found in {column} and converted to NaN. These rows will be dropped.")
            print(df[df[column].isnull()])
        
        # Check if there are any -1 values in the column
        if (df[column] == -1).any():
            # Print a message and the rows with -1 values
            print(f"Warning: Rows with -1 values found in {column}. These rows will be dropped:")
            print(df[df[column] == -1])
            
            df = df[df[column] != -1]

        df = df[df[column] != -1]
        df = df.dropna(subset=[column])
        df[column] = df[column].astype(int)


    # Calculate accuracy, precision, and recall
    accuracy = accuracy_score(df['true_label'], df['pred_label'])
    precision = precision_score(df['true_label'], df['pred_label'], zero_division=1)
    recall = recall_score(df['true_label'], df['pred_label'], zero_division=1)

    accuracy = round(accuracy, sig_fig)
    precision = round(precision, sig_fig)
    recall = round(recall, sig_fig)

    # Create a summary table
    summary = pd.DataFrame({
        'Experiment Name': [experiment_name],
        'Accuracy': [accuracy],
        'Precision': [precision],
        'Recall': [recall]
    })
    
    # Write the summary table to the output file
    summary.to_csv(output_file, index=False)
    print(f"Results of {experiment_name} written to {output_file}")

    return summary

def main():
    calculate_all_results("./results/all_results.csv")
    return
    cwe_target = 190
    # TODO specify the input and output file
    calculate_target_stats(
        f"{DEFAULT_QUERY_MODEL}_{cwe_target} base query",
        f"./results/scanner_base_{cwe_target}.csv",
        f"./stats/base_{cwe_target}.log"
    )

    calculate_target_stats(
        f"{DEFAULT_QUERY_MODEL}_{cwe_target} rag indexed query",
        f"./results/scanner_rag_{cwe_target}_cleaned.csv",
        f"./stats/rag_{cwe_target}.log"
    )

    calculate_target_stats(
        f"{DEFAULT_QUERY_MODEL}_{cwe_target} llama index query",
        f"./results/scanner_llama_{cwe_target}_cleaned.csv",
        f"./stats/llama_index_{cwe_target}.log"
    )

    # TODO WRITE A FUNCTION THAT AGGREGATES ALL THE LINES AND PRINT



if __name__ == "__main__":
    main()
