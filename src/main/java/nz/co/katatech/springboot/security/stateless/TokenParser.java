package nz.co.katatech.springboot.security.stateless;

public interface TokenParser<T> {

    String generate( T subject );

    T parse( String token );

}
