#include <stdio.h>
#include <omp.h>
#include <fstream>
#include <chrono>   
#define min(a, b) a <= b ? a : b
#define max(a, b) a >= b ? a : b
#define MODE static, 4

struct Image{
    unsigned char* data;
    int width;
    int height;
    bool isp5;
    ulong count;

    Image(int width, int height, bool isp5){
        this->width = width;
        this->height = height;
        this->isp5 = isp5;
        this->count = (ulong)(isp5 ? 1 : 3) * height * width;
        this->data = (unsigned char*)malloc(count * sizeof(unsigned char));
    }
    Image(){}   
};


Image readImage(FILE *fp){
    getc(fp);
    bool p5 = false;    
    if(getc(fp) == 53){
        p5 = true;
    }
    
    getc(fp);
    int width, height, grayscale;
    fscanf(fp, "%d%d%d", &width, &height, &grayscale);
    getc(fp);

    Image result(width, height, p5);
    fread(result.data, sizeof(unsigned char), result.count, fp);
    return result;    
}

void printImage(Image img, FILE *fp){
    if(img.isp5){
        fputs((std::string("P5\n") + std::to_string(img.width) + " " + std::to_string(img.height) + "\n" + std::to_string(255) + "\n").c_str(), fp);
    }else{
        fputs((std::string("P6\n") + std::to_string(img.width) + " " + std::to_string(img.height) + "\n" + std::to_string(255) + "\n").c_str(), fp);
    }
    fwrite(img.data, sizeof(unsigned char), img.count, fp);
    free(img.data);
}

void handleImage(Image img, double coff){
    ulong deleteCount = (ulong)(img.width) * img.height * coff;
    ulong counts[256][3] = {0};
    // sort
    #pragma omp parallel shared(counts, img) 
    {   
        ulong buffer[256][3] = {0};
        #pragma omp for schedule(MODE)
        for(int i = 0 ;i < img.count;i++){
            if(img.isp5){
                buffer[img.data[i]][0]++;
            }else{
                buffer[img.data[i]][i % 3]++;
            }
        }
        #pragma omp critical
        for(int i = 0; i < 256;i++){
            for(int g = 0; g < 3;g++){
                counts[i][g] += buffer[i][g];
            }
        }
    }
    // min/max
    int mn = 255;
    int mx = 0;
    
    for(int g = 0; g < 3 || g < 1 && img.isp5;g++){
        int ost = deleteCount;
        for(int i = 0; i < 256;i++){
            int v = min(ost, counts[i][g]);
            ost -= counts[i][g];
            counts[i][g] -= v;
            if(ost < 0){
                mn = min(mn, i);
                break;
            }
        }
        ost = deleteCount;
        for(int i = 255; i >= 0;i--){
            int v = min(ost, counts[i][g]);
            ost -= counts[i][g];
            counts[i][g] -= v;
            if(ost < 0){
                mx = max(mx, i);
                break;
            }
        }
    }
    if(mn >= mx){
        printf("Image consists only of one color or coefficient is too big. Image was not handled.\n");
        return;
    }
    // normalize
    #pragma omp parallel for schedule(MODE) shared(img, mn, mx)
    for(int i = 0 ;i < img.count;i++){ 
        int value = img.data[i];
        img.data[i] = (value < mn) ? (0) : ((value > mx) ? 255 : (255 * (value - mn)) / (mx - mn));
    }

}

int main(int argc, char **argv){
    if(argc != 5){  
        printf("Wrong arguments count, expected: thread count, input, output, coefficient\n");
        return 0;
    }   

    int thread_count;
    try{
        thread_count = std::atoi(argv[1]);
        if(thread_count < 0){
            printf("Thread count can not be negative\n");
            return 0;
        }
    }catch(...){
        printf("Wrong argument - thread count\n");
        return 0;
    }   
    
    #ifdef _OPENMP
        if(thread_count != 0){
            omp_set_num_threads(thread_count);
        }else{
            thread_count = omp_get_max_threads();
            printf("Default number of threads is %d\n", thread_count);
        }
    #endif
    Image image;
    try{
        FILE *fp = fopen(argv[2], "rb");
        if(!fp){
            printf("Input file is not accessible\n");
            return 0;
        }
        image = readImage(fp);
        fclose(fp);
    }catch(...){
        printf("input file is not correct\n");
    }    
    double coff;
    try{
        coff = std::atof(argv[4]);
        if(coff < 0 || coff >= 0.5){
            printf("Incorrect coefficient value\n");
            return 0;
        }
    }catch(...){
        printf("Wrong argument - coefficient\n");
        return 0;
    }
    
    double start;
    auto startChrono = std::chrono::steady_clock::now();
    #ifdef _OPENMP
        start = omp_get_wtime();
    #endif
    handleImage(image, coff);
    #ifdef _OPENMP
        printf("Time (%i thread(s)): %g ms\n", thread_count, omp_get_wtime() - start);
    #else
        printf("Time: %g ms\n", std::chrono::duration<double>(std::chrono::steady_clock::now() - startChrono).count());
    #endif

    try{
        FILE* fp;
        fp = fopen(argv[3], "wb"); 
        if(!fp){
            printf("Output file is not accessible\n");
            return 0;
        }
        printImage(image, fp);
        fclose(fp);
    }catch(...){
        printf("Can not save image\n");
    }   
}