% Choudhury Noor, Cardy Wei
% ECE 455 - Computer Security
% Final Project

%% Load
f = fopen('devrnd_samples.txt','r');
s = fscanf(f,'%s');
bits_linux_full = nan(size(s));
for i = [1:length(s)]
	bits_linux_full(i) = (str2double(s(i)));
end
fclose(f);

f = fopen('custom_samples.txt','r');
s = fscanf(f,'%s');
bits_custom_full = nan(size(s));
for i = [1:length(s)]
	bits_custom_full(i) = (str2double(s(i)));
end
fclose(f);

%% Analyze
% entropy vs chunk
xaxis = logspace(1,4.5,100);
yaxis_Hx = [];
yaxis_Hy = [];
for i = xaxis
	i = floor(i);
	Hy = [];
	Hx = [];
	for j = [1:floor(length(bits_linux_full)./i)]
		bits_linux = bits_linux_full((j-1).*i+1:j*i);
		bits_custom = bits_custom_full((j-1).*i+1:j*i);

		probs = [bits_linux;~bits_linux]*[bits_custom;~bits_custom].'./length(bits_custom);

		Hy = [Hy, -sum(sum(probs,1).*log2(sum(probs,1)))];
		Hx = [Hx, -sum(sum(probs,2).*log2(sum(probs,2)))];
	end
	yaxis_Hx = [yaxis_Hx, mean(Hx)];
	yaxis_Hy = [yaxis_Hy, mean(Hy)];
end
figure();
semilogx(xaxis,yaxis_Hx);
hold on;
semilogx(xaxis,yaxis_Hy);
xlabel('chunk size (bits)');
ylabel('bits');
title('Shannon Entropy');
legend('dev\\random','rng\_custom');

% mutual info between chunks
xaxis = logspace(1,4.5,100);
yaxis_I_linux = [];
yaxis_I_custom = [];

% linux
for i = xaxis
	i = floor(i);
	I = zeros(size([1:floor(length(bits_linux_full)./i)-1]));
	idx = 1;
	for j = [1:floor(length(bits_linux_full)./i)-1]
		bits1 = bits_linux_full((j-1).*i+1:j*i);
		bits2 = bits_linux_full((j).*i+1:(j+1)*i);
		
		probs = [bits1;~bits1]*[bits2;~bits2].'./length(bits2);
		
		Hyx =  -0.5.*sum( probs(1,:)./sum(probs(1,:)).*(log2(probs(1,:)./sum(probs(1,:))))) ...
			+ -0.5.*sum( probs(2,:)./sum(probs(2,:)).*(log2(probs(2,:)./sum(probs(2,:)))));
		
		Hy = -sum(sum(probs,1).*log2(sum(probs,1)));
		I(idx) = Hy - Hyx;
		idx = idx +1;
	end
	yaxis_I_linux = [yaxis_I_linux, mean(I)];
end

% rng_custom
for i = xaxis
	i = floor(i);
	I = zeros(size([1:floor(length(bits_custom_full)./i)-1]));
	idx = 1;
	for j = [1:floor(length(bits_custom_full)./i)-1]
		bits1 = bits_custom_full((j-1).*i+1:j*i);
		bits2 = bits_custom_full((j).*i+1:(j+1)*i);
		
		probs = [bits1;~bits1]*[bits2;~bits2].'./length(bits2);
		
		Hyx =  -0.5.*sum( probs(1,:)./sum(probs(1,:)).*(log2(probs(1,:)./sum(probs(1,:))))) ...
			+ -0.5.*sum( probs(2,:)./sum(probs(2,:)).*(log2(probs(2,:)./sum(probs(2,:)))));
		
		Hy = -sum(sum(probs,1).*log2(sum(probs,1)));
		I(idx) = Hy - Hyx;
		idx = idx +1;
	end
	yaxis_I_custom = [yaxis_I_custom, mean(I)];
end

figure();
semilogx(xaxis,yaxis_I_linux);
hold on;
semilogx(xaxis,yaxis_I_custom);
xlabel('chunk size (bits)');
ylabel('bits');
title('Mutual Information between adjacent chunks');
legend('dev\\random','rng\_custom');
