import numpy as np

def get_logistic_sequence(initial_value, logistic_parameter_a, height, width):
    sequence_length = width * height
    
    # Initialize sequences
    logistic_original_sequence = np.arange(sequence_length)
    logistic_sequence = np.ones(sequence_length) * initial_value
    
    # Generate logistic sequence
    for i in range(1, sequence_length):
        logistic_sequence[i] = logistic_parameter_a * logistic_sequence[i-1] * (1 - logistic_sequence[i-1])
    
    # Combine and sort sequences
    logistic_sequence_combine = np.vstack((logistic_sequence, logistic_original_sequence))
    
    # Sort based on first row
    sorted_indices = np.argsort(logistic_sequence_combine[0])
    logistic_sequence_combine = logistic_sequence_combine[:, sorted_indices]
    
    # Return the sorted original sequence indices
    return logistic_sequence_combine[1].astype(np.int32)