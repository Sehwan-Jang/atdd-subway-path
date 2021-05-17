package wooteco.subway.member.application;

import org.springframework.stereotype.Service;
import wooteco.subway.auth.application.AuthService;
import wooteco.subway.exception.member.NotRegisteredMemberException;
import wooteco.subway.member.dao.MemberDao;
import wooteco.subway.member.domain.Member;
import wooteco.subway.member.dto.MemberRequest;
import wooteco.subway.member.dto.MemberResponse;

@Service
public class MemberService {
    private final MemberDao memberDao;
    private final AuthService authService;

    public MemberService(MemberDao memberDao, AuthService authService) {
        this.memberDao = memberDao;
        this.authService = authService;
    }

    public Long createMember(MemberRequest request) {
        String encodedPassword = authService.encodePassword(request.getPassword());
        return memberDao.insert(request.toEncodedMember(encodedPassword));
    }

    public MemberResponse findMember(Long id) {
        Member member = memberDao.findById(id).orElseThrow(NotRegisteredMemberException::new);
        return MemberResponse.of(member);
    }

    public void updateMember(Long id, MemberRequest memberRequest) {
        memberDao.update(new Member(id, memberRequest.getEmail(), memberRequest.getPassword(), memberRequest.getAge()));
    }

    public void deleteMember(Long id) {
        memberDao.deleteById(id);
    }
}
