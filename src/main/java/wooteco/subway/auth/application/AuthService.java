package wooteco.subway.auth.application;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import wooteco.subway.auth.dto.TokenRequest;
import wooteco.subway.auth.dto.TokenResponse;
import wooteco.subway.auth.infrastructure.JwtTokenProvider;
import wooteco.subway.exception.auth.IllegalTokenException;
import wooteco.subway.exception.auth.LoginFailEmailException;
import wooteco.subway.exception.auth.LoginWrongPasswordException;
import wooteco.subway.exception.member.NotRegisteredMemberException;
import wooteco.subway.member.dao.MemberDao;
import wooteco.subway.member.domain.Member;

@Service
public class AuthService {

    private final JwtTokenProvider tokenProvider;
    private final MemberDao memberDao;
    private final PasswordEncoder passwordEncoder;

    public AuthService(JwtTokenProvider tokenProvider, MemberDao memberDao, PasswordEncoder passwordEncoder) {
        this.tokenProvider = tokenProvider;
        this.memberDao = memberDao;
        this.passwordEncoder = passwordEncoder;
    }

    public TokenResponse createToken(TokenRequest tokenRequest) {
        String email = tokenRequest.getEmail();
        String accessToken = tokenProvider.createToken(email);
        checkAvailableLogin(tokenRequest);
        return new TokenResponse(accessToken);
    }

    private void checkAvailableLogin(TokenRequest tokenRequest) {
        String email = tokenRequest.getEmail();
        String password = tokenRequest.getPassword();
        Member member = memberDao.findByEmail(email).orElseThrow(LoginFailEmailException::new);
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new LoginWrongPasswordException();
        }
    }

    public String getPayLoad(String tokenName) {
        return tokenProvider.getPayload(tokenName);
    }

    public Long findMemberIdByEmail(String email) {
        Member member =  memberDao.findByEmail(email).orElseThrow(NotRegisteredMemberException::new);
        return member.getId();
    }

    public void checkAvailableToken(String token) {
        if (!tokenProvider.validateToken(token)) {
            throw new IllegalTokenException();
        }
    }

    public String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }
}
