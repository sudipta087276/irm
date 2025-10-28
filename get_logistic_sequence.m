function [logistic_sequence_output] = get_logistic_sequence(initial_value,logistic_parameter_a,height,width)
    
    logistic_original_sequence = 0 : width*height-1;            
    logistic_sequence=ones(1,width*height)*initial_value;  
    
    for i=2:width*height
        logistic_sequence(i)=logistic_parameter_a*logistic_sequence(i-1)*(1-logistic_sequence(i-1));
    end
    logistic_sequence_combine=[logistic_sequence;logistic_original_sequence];
    for i = 1 : width*height - 1
        flag=0;
        for j = 1 : width*height - i       
            if logistic_sequence_combine(1,j)>logistic_sequence_combine(1,j+1)
                temp=logistic_sequence_combine(:,j);
                logistic_sequence_combine(:,j)=logistic_sequence_combine(:,j+1);
                logistic_sequence_combine(:,j+1)=temp;
                flag=1;
            end
        end
        if(~flag)    
            break;
        end
    end
    % load('logistic_sequence_combine.mat');
    logistic_sequence_output = logistic_sequence_combine(2,:);
    
end

