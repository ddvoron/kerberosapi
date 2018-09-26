package controller;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;

import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.web.servlet.config.annotation.*;


@Configuration
@ComponentScan("controller")
@EnableWebMvc
@EnableSpringDataWebSupport
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("*").addResourceLocations("/", "classpath:/");
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index.html");
    }

    /**
     * Specific configuration for Jboss 6.x
     */
    @Override
    public Validator getValidator() {
        return new Validator() {

            @Override
            public void validate(Object target, Errors errors) {
				/*emtpy*/
            }

            @Override
            public boolean supports(Class<?> clazz) {
                return false;
            }
        };
    }

    //TODO: remove
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*").allowedMethods("HEAD", "GET", "PUT", "POST", "DELETE", "PATCH");
    }
}
