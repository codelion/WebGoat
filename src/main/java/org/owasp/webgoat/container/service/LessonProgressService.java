package org.owasp.webgoat.container.service;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.owasp.webgoat.container.lessons.Assignment;
import org.owasp.webgoat.container.session.WebSession;
import org.owasp.webgoat.container.users.UserProgressRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * LessonProgressService class.
 *
 */
@Controller
@RequiredArgsConstructor
public class LessonProgressService {

  private final UserProgressRepository userTrackerRepository;
  private final WebSession webSession;

  /**
   * Endpoint for fetching the complete lesson overview which informs the user about whether all the
   * assignments are solved. Used as the last page of the lesson to generate a lesson overview.
   *
   * @return list of assignments
   */
  @RequestMapping(value = "/service/lessonoverview.mvc", method = RequestMethod.GET, produces = "application/json")
  @ResponseBody
  public List<LessonOverview> lessonOverview() {
    var userTracker = userTrackerRepository.findByUser(webSession.getUserName());
    var currentLesson = webSession.getCurrentLesson();

    if (currentLesson != null) {
      var lessonTracker = userTracker.getLessonProgress(currentLesson);
      return lessonTracker.getLessonOverview().entrySet().stream()
          .map(entry -> new LessonOverview(entry.getKey(), entry.getValue()))
          .toList();
    }
    return List.of();
  }

  @AllArgsConstructor
  @Getter
  private static class LessonOverview {

    private Assignment assignment;
    private Boolean solved;
  }
}
